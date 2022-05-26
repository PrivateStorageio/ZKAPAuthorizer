# coding: utf-8
# Copyright 2019 PrivateStorage.io, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Tests for ``_zkapauthorizer.model``.
"""

from datetime import datetime, timedelta
from functools import partial
from io import BytesIO
from itertools import count
from sqlite3 import Connection, OperationalError, connect
from typing import TypeVar

import cbor2
from hypothesis import assume, given, note
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)
from hypothesis.strategies import (
    booleans,
    builds,
    data,
    integers,
    lists,
    randoms,
    sampled_from,
    text,
    timedeltas,
    tuples,
)
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    Equals,
    HasLength,
    Is,
    IsInstance,
    MatchesAll,
    MatchesStructure,
)
from testtools.twistedsupport import failed, succeeded
from twisted.internet.defer import Deferred, succeed

from ..model import (
    DoubleSpend,
    LeaseMaintenanceActivity,
    NotEmpty,
    NotEnoughTokens,
    Pass,
    Pending,
    Redeemed,
    UnblindedToken,
    Voucher,
    VoucherStore,
    aware_now,
    memory_connect,
    with_cursor_async,
)
from ..recover import (
    RecoveryStages,
    RecoveryState,
    StatefulRecoverer,
    make_canned_downloader,
    recover_snapshot,
    statements_from_snapshot,
)
from ..replicate import (
    Change,
    EventStream,
    add_events,
    get_events,
    prune_events_to,
    with_replication,
)
from .common import from_awaitable
from .fixtures import TempDir, TemporaryVoucherStore
from .matchers import raises
from .strategies import (
    aware_datetimes,
    deletes,
    dummy_ristretto_keys,
    inserts,
    pass_counts,
    posix_safe_datetimes,
    random_tokens,
    sql_identifiers,
    sql_values,
    tables,
    tahoe_configs,
    unblinded_tokens,
    updates,
    voucher_counters,
    voucher_objects,
    vouchers,
    zkaps,
)

_T = TypeVar("_T")


async def fail(cursor) -> None:
    raise Exception("Should not be called")


class WithCursorAsyncTests(TestCase):
    """
    Tests for ``with_cursor_async``.
    """

    def test_exception(self) -> None:
        """
        A function decorated with ``with_cursor_async`` returns a coroutine that
        raises the same exception as the decorated function and the
        transaction is rolled back.
        """

        class SomeException(Exception):
            pass

        class Database:
            _connection: Connection = connect(":memory:")

            @with_cursor_async
            async def f(self, cursor) -> None:
                cursor.execute("CREATE TABLE [bad] ([a] INT)")
                cursor.execute("INSERT INTO [bad] VALUES (1)")
                raise SomeException()

        self.assertThat(
            from_awaitable(Database().f()),
            failed(AfterPreprocessing(lambda f: f.value, IsInstance(SomeException))),
        )

        cursor = Database._connection.cursor()
        self.assertThat(
            lambda: cursor.execute("SELECT * FROM [bad]"),
            raises(OperationalError),
        )

    def test_success(self) -> None:
        """
        A function decorated with ``with_cursor_async`` returns a coroutine that
        succeeds with the same result as the decorated function and commits
        the transaction.
        """

        class Database:
            _connection: Connection = connect(":memory:")
            expected = object()

            @with_cursor_async
            async def f(self, cursor):
                cursor.execute("CREATE TABLE [good] ([a] INT)")
                cursor.execute("INSERT INTO [good] VALUES (1)")
                return self.expected

        self.assertThat(
            from_awaitable(Database().f()),
            succeeded(Is(Database.expected)),
        )
        cursor = Database._connection.cursor()
        cursor.execute("SELECT * FROM [good]")
        self.assertThat(
            cursor.fetchall(),
            Equals([(1,)]),
        )

    def test_async(self) -> None:
        """
        The given function can return an ``Awaitable`` and the transaction will
        not be committed until it has a result.
        """
        # If we want to observe transactional side-effects then we need
        # transactionally independent views on the database.  For SQLite3 (at
        # least), this means two different connections to the same database.
        path = self.useFixture(TempDir()).join("async")
        conn_a = memory_connect(path)
        conn_b = memory_connect(path)

        class Database:
            _connection: Connection = conn_a
            expected = object()
            task: Deferred[None] = Deferred()

            @with_cursor_async
            async def f(self, cursor_a):
                # Have an observable effect
                cursor_a.execute("CREATE TABLE [foo] ([a] INT)")
                cursor_a.execute("INSERT INTO [foo] VALUES (1)")
                # The transaction is still open while we wait.
                await self.task
                return self.expected

        # Start the asynchronous task but don't wait on it so that we can
        # assert stuff in parallel.
        db = Database()
        coro_d = from_awaitable(db.f())

        # Since the asynchronous task hasn't completed, its transaction hasn't
        # committed and there is no foo table to select from.  A query on the
        # second connection can confirm this.
        cursor_b = conn_b.cursor()
        self.assertThat(
            lambda: cursor_b.execute("SELECT [a] FROM [foo]"),
            raises(OperationalError),
        )

        # Allow the asynchronous task to complete - which should also cause
        # the transaction to be committed.
        Database.task.callback(None)

        # Now we can wait for the task to finish.  Also, we expect to get back
        # the value from the function we passed in.
        self.assertThat(coro_d, succeeded(Equals(Database.expected)))

        # So we can see the table and row that were created in it.
        cursor_b.execute("SELECT [a] FROM [foo]")
        self.assertThat(
            cursor_b.fetchall(),
            Equals([(1,)]),
        )


class VoucherStoreCallIfEmptyTests(TestCase):
    """
    Tests for ``VoucherStore.call_if_empty``.
    """

    def setup_example(self) -> None:
        self.store_fixture = self.useFixture(
            TemporaryVoucherStore(
                get_now=aware_now,
            ),
        )

    def test_empty(self) -> None:
        """
        If a ``VoucherStore`` is instantiated and there was no existing database
        then it is empty.
        """
        self.setup_example()
        store = self.store_fixture.store

        async def side_effect(cursor):
            cursor.execute("CREATE TABLE [it_ran] (a INT)")
            cursor.execute("INSERT INTO [it_ran] VALUES (1)")
            return True

        self.assertThat(
            Deferred.fromCoroutine(store.call_if_empty(side_effect)),
            succeeded(Equals(True)),
        )

        async def check_side_effect(cursor):
            rows = cursor.execute("SELECT * FROM [it_ran]")
            rows = cursor.fetchall()
            return rows

        self.assertThat(
            Deferred.fromCoroutine(store.call_if_empty(check_side_effect)),
            succeeded(Equals([(1,)])),
        )

    @given(
        voucher=vouchers(),
        tokens=lists(random_tokens(), min_size=1, max_size=10, unique=True),
    )
    def test_not_empty_if_any_vouchers(self, voucher, tokens) -> None:
        """
        If there are any vouchers in the database a ``VoucherStore`` is using then
        it is not empty.
        """
        self.store_fixture.store.add(
            voucher,
            expected_tokens=len(tokens),
            counter=0,
            get_tokens=lambda: tokens,
        )
        self.assertThat(
            Deferred.fromCoroutine(self.store_fixture.store.call_if_empty(fail)),
            failed(AfterPreprocessing(lambda f: f.value, IsInstance(NotEmpty))),
        )

    @given(
        voucher=vouchers(),
        num_passes=integers(min_value=1, max_value=10),
    )
    def test_not_empty_if_any_spendable_tokens(self, voucher, num_passes) -> None:
        """
        If there are spendable ZKAPs in the database a ``VoucherStore`` is using
        then it is not empty.
        """
        d = self.store_fixture.redeem(voucher, num_passes)
        self.assertThat(d, succeeded(Always()))
        self.assertThat(
            Deferred.fromCoroutine(self.store_fixture.store.call_if_empty(fail)),
            failed(AfterPreprocessing(lambda f: f.value, IsInstance(NotEmpty))),
        )

    @given(
        voucher=vouchers(),
        num_passes=integers(min_value=1, max_value=10),
    )
    def test_not_empty_if_any_unspendable_tokens(self, voucher, num_passes) -> None:
        """
        If there are unspendable ZKAPs in the database a ``VoucherStore`` is using
        then it is not empty.
        """
        d = self.store_fixture.redeem(voucher, num_passes)
        self.assertThat(d, succeeded(Always()))

        tokens = self.store_fixture.store.get_unblinded_tokens(num_passes)
        self.store_fixture.store.invalidate_unblinded_tokens("anything", tokens)

        self.assertThat(
            Deferred.fromCoroutine(self.store_fixture.store.call_if_empty(fail)),
            failed(AfterPreprocessing(lambda f: f.value, IsInstance(NotEmpty))),
        )


class VoucherStoreTests(TestCase):
    """
    Tests for ``VoucherStore``.
    """

    @given(integers(min_value=1))
    def test_reject_naive_datetime(self, pass_value) -> None:
        """
        ``VoucherStore`` raises ``TypeError`` on initialization if given a ``now``
        that returns a datetime without a timezone.
        """
        naive_now = datetime.now
        db_path = self.useFixture(TempDir()).join("reject-naive.db")
        conn = with_replication(memory_connect(db_path), False)
        self.assertThat(
            lambda: VoucherStore(pass_value, naive_now, conn),
            raises(TypeError),
        )

    @given(tahoe_configs(), aware_datetimes(), vouchers())
    def test_get_missing(self, get_config, now, voucher) -> None:
        """
        ``VoucherStore.get`` raises ``KeyError`` when called with a
        voucher not previously added to the store.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        self.assertThat(
            lambda: store.get(voucher),
            raises(KeyError),
        )

    @given(
        tahoe_configs(),
        vouchers(),
        lists(random_tokens(), min_size=1, unique=True),
        aware_datetimes(),
    )
    def test_add(self, get_config, voucher, tokens, now) -> None:
        """
        ``VoucherStore.get`` returns a ``Voucher`` representing a voucher
        previously added to the store with ``VoucherStore.add``.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        store.add(voucher, len(tokens), 0, lambda: tokens)
        self.assertThat(
            store.get(voucher),
            MatchesStructure(
                number=Equals(voucher),
                expected_tokens=Equals(len(tokens)),
                state=Equals(Pending(counter=0)),
                created=Equals(now),
            ),
        )

    @given(
        tahoe_configs(),
        vouchers(),
        lists(voucher_counters(), unique=True, min_size=2, max_size=2),
        lists(random_tokens(), min_size=2, unique=True),
        aware_datetimes(),
    )
    def test_add_with_distinct_counters(
        self, get_config, voucher, counters, tokens, now
    ) -> None:
        """
        ``VoucherStore.add`` adds new tokens to the store when passed the same
        voucher but a different counter value.
        """
        counter_a = counters[0]
        counter_b = counters[1]
        tokens_a = tokens[: len(tokens) // 2]
        tokens_b = tokens[len(tokens) // 2 :]

        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        # We only have to get the expected_tokens value (len(tokens)) right on
        # the first call.
        added_tokens_a = store.add(voucher, len(tokens), counter_a, lambda: tokens_a)
        added_tokens_b = store.add(voucher, 0, counter_b, lambda: tokens_b)

        self.assertThat(
            store.get(voucher),
            MatchesStructure(
                number=Equals(voucher),
                expected_tokens=Equals(len(tokens)),
                state=Equals(Pending(counter=0)),
                created=Equals(now),
            ),
        )

        self.assertThat(tokens_a, Equals(added_tokens_a))
        self.assertThat(tokens_b, Equals(added_tokens_b))

    @given(
        tahoe_configs(),
        vouchers(),
        aware_datetimes(),
        lists(random_tokens(), min_size=1, unique=True),
    )
    def test_add_idempotent(self, get_config, voucher, now, tokens) -> None:
        """
        More than one call to ``VoucherStore.add`` with the same argument results
        in the same state as a single call.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        first_tokens = store.add(
            voucher,
            expected_tokens=len(tokens),
            counter=0,
            get_tokens=lambda: tokens,
        )
        second_tokens = store.add(
            voucher,
            # The voucher should already exists in the store so the
            # expected_tokens value supplied here is ignored.
            expected_tokens=0,
            counter=0,
            # Likewise, no need to generate tokens here because counter value
            # 0 was already added and tokens were generated then.  If
            # get_tokens were called here, it would be an error.
            get_tokens=None,
        )
        self.assertThat(
            store.get(voucher),
            MatchesStructure(
                number=Equals(voucher),
                expected_tokens=Equals(len(tokens)),
                created=Equals(now),
                state=Equals(Pending(counter=0)),
            ),
        )
        self.assertThat(
            first_tokens,
            Equals(tokens),
        )
        self.assertThat(
            second_tokens,
            Equals(tokens),
        )

    @given(tahoe_configs(), aware_datetimes(), lists(vouchers(), unique=True), data())
    def test_list(self, get_config, now, vouchers, data) -> None:
        """
        ``VoucherStore.list`` returns a ``list`` containing a ``Voucher`` object
        for each voucher previously added.
        """
        tokens = iter(
            data.draw(
                lists(
                    random_tokens(),
                    unique=True,
                    min_size=len(vouchers),
                    max_size=len(vouchers),
                ),
            )
        )
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        for voucher in vouchers:
            store.add(
                voucher,
                expected_tokens=1,
                counter=0,
                get_tokens=lambda: [next(tokens)],
            )

        self.assertThat(
            store.list(),
            Equals(
                list(
                    Voucher(number, expected_tokens=1, created=now)
                    for number in vouchers
                )
            ),
        )


class VoucherStoreSnapshotTests(TestCase):
    """
    Tests for ``VoucherStore.snapshot``.
    """

    @given(
        posix_safe_datetimes(),
        vouchers(),
        integers(min_value=1, max_value=2**63 - 1),
        lists(random_tokens(), unique=True),
    )
    def test_vouchers(self, now, voucher, expected, tokens) -> None:
        """
        Vouchers are present in the snapshot.
        """
        store = self.useFixture(TemporaryVoucherStore(get_now=lambda: now)).store
        store.add(voucher, expected, 0, lambda: tokens)
        statements = statements_from_snapshot(lambda: BytesIO(store.snapshot()))
        connection = connect(":memory:")
        cursor = connection.cursor()
        with connection:
            recover_snapshot(statements, cursor)

        recovered = VoucherStore.from_connection(
            store.pass_value,
            store.now,
            with_replication(connection, False),
        )
        self.assertThat(
            recovered.get(voucher),
            Equals(
                Voucher(voucher, expected, now),
            ),
        )


class UnblindedTokenStateMachine(RuleBasedStateMachine):
    """
    Transition rules for a state machine corresponding to the state of
    unblinded tokens in a ``VoucherStore`` - usable, in-use, spent, invalid,
    etc.

    :ivar num_vouchers_redeemed: The total number of vouchers that have been
        redeemed successfully by this machine.
    """

    def __init__(self, case) -> None:
        super(UnblindedTokenStateMachine, self).__init__()
        self.case = case
        self.configless = TemporaryVoucherStore(
            # Time probably not actually relevant to this state machine.
            get_now=aware_now,
        )
        self.configless.setUp()

        self.num_vouchers_redeemed: int = 0
        self.available = 0
        self.using: list[UnblindedToken] = []
        self.spent: list[UnblindedToken] = []
        self.invalid: list[UnblindedToken] = []

    def teardown(self) -> None:
        self.configless.cleanUp()

    @rule(voucher=vouchers(), num_passes=pass_counts())
    def redeem_voucher(self, voucher, num_passes) -> None:
        """
        A voucher can be redeemed, adding more unblinded tokens to the store.
        """
        try:
            self.configless.store.get(voucher)
        except KeyError:
            pass
        else:
            # Cannot redeem a voucher more than once.  We redeemed this one
            # already.
            assume(False)

        self.case.assertThat(
            self.configless.redeem(voucher, num_passes),
            succeeded(Always()),
        )
        self.available += num_passes
        self.num_vouchers_redeemed += 1

    @rule(num_passes=pass_counts())
    def get_passes(self, num_passes) -> None:
        """
        Some passes can be requested from the store.  The resulting passes are not
        spent, invalid, or already in-use.
        """
        assume(num_passes <= self.available)
        tokens = self.configless.store.get_unblinded_tokens(num_passes)
        note("get_passes: {}".format(tokens))

        # No tokens we are currently using may be returned again.  Nor may
        # tokens which have reached a terminal state of spent or invalid.
        unavailable = set(self.using) | set(self.spent) | set(self.invalid)

        self.case.assertThat(
            tokens,
            MatchesAll(
                HasLength(num_passes),
                AfterPreprocessing(
                    lambda t: set(t) & unavailable,
                    Equals(set()),
                ),
            ),
        )
        self.using.extend(tokens)
        self.available -= num_passes

    @rule(excess_passes=pass_counts())
    def not_enough_passes(self, excess_passes) -> None:
        """
        If an attempt is made to get more passes than are available,
        ``get_unblinded_tokens`` raises ``NotEnoughTokens``.
        """
        self.case.assertThat(
            lambda: self.configless.store.get_unblinded_tokens(
                self.available + excess_passes,
            ),
            raises(NotEnoughTokens),
        )

    @precondition(lambda self: len(self.using) > 0)
    @rule(random=randoms(), data=data())
    def spend_passes(self, random, data) -> None:
        """
        Some in-use passes can be discarded.
        """
        self.using, to_spend = random_slice(self.using, random, data)
        note("spend_passes: {}".format(to_spend))
        self.configless.store.discard_unblinded_tokens(to_spend)

    @precondition(lambda self: len(self.using) > 0)
    @rule(random=randoms(), data=data())
    def reset_passes(self, random, data) -> None:
        """
        Some in-use passes can be returned to not-in-use state.
        """
        self.using, to_reset = random_slice(self.using, random, data)
        note("reset_passes: {}".format(to_reset))
        self.configless.store.reset_unblinded_tokens(to_reset)
        self.available += len(to_reset)

    @precondition(lambda self: len(self.using) > 0)
    @rule(random=randoms(), data=data())
    def invalidate_passes(self, random, data) -> None:
        """
        Some in-use passes are unusable and should be set aside.
        """
        self.using, to_invalidate = random_slice(self.using, random, data)
        note("invalidate_passes: {}".format(to_invalidate))
        self.configless.store.invalidate_unblinded_tokens(
            "reason",
            to_invalidate,
        )
        self.invalid.extend(to_invalidate)

    @rule()
    def discard_ephemeral_state(self) -> None:
        """
        Reset all state that cannot outlive a single process, simulating a
        restart.

        XXX We have to reach into the guts of ``VoucherStore`` to do this
        because we're using an in-memory database.  We can't just open a new
        ``VoucherStore``. :/ Perhaps we should use an on-disk database...  Or
        maybe this is a good argument for using an explicitly attached
        temporary database instead of the built-in ``temp`` database.
        """
        cursor = self.configless.store._connection.cursor()
        with self.configless.store._connection:
            cursor.execute("DELETE FROM [in-use]")
        self.available += len(self.using)
        del self.using[:]

    @invariant()
    def random_token_count(self) -> None:
        """
        ``VoucherStore.random_token_count`` returns ``0``.

        The state machine currently jumps over all intermediate states where
        this function could legitimately return non-zero.  It might be nice to
        split up the ``get_passes`` rule so that we could see other values
        sometimes.
        """
        self.case.assertThat(
            self.configless.store.count_random_tokens(),
            Equals(0),
        )

    @invariant()
    def unblinded_token_count(self) -> None:
        """
        ``VoucherStore.count_unblinded_tokens`` returns the number of tokens
        available to be spent.
        """
        self.case.assertThat(
            self.configless.store.count_unblinded_tokens(),
            Equals(self.available),
        )

    @invariant()
    def check_empty(self) -> None:
        """
        ``VoucherStore.call_if_empty`` succeeds until any voucher is redeemed and
        then raises ``NotEmpty``.
        """
        if self.num_vouchers_redeemed == 0:
            self.case.assertThat(
                Deferred.fromCoroutine(
                    self.configless.store.call_if_empty(lambda cursor: succeed(True))
                ),
                succeeded(Equals(True)),
            )
        else:
            self.case.assertThat(
                Deferred.fromCoroutine(self.configless.store.call_if_empty(fail)),
                failed(
                    AfterPreprocessing(lambda f: f.value, IsInstance(NotEmpty)),
                ),
            )

    @invariant()
    def report_state(self) -> None:
        note(
            "available={} using={} invalid={} spent={}".format(
                self.available,
                len(self.using),
                len(self.invalid),
                len(self.spent),
            )
        )


def random_slice(taken_from, random, data):
    """
    Divide ``taken_from`` into two pieces with elements randomly assigned to
    one piece or the other.

    :param list taken_from: A list of elements to divide.  This will be
        mutated.

    :param random: A ``random`` module-alike.

    :param data: A Hypothesis data object for drawing values.

    :return: A two-tuple of the two resulting lists.
    """
    count = data.draw(integers(min_value=1, max_value=len(taken_from)))
    random.shuffle(taken_from)
    remaining = taken_from[:-count]
    sliced = taken_from[-count:]
    return remaining, sliced


class UnblindedTokenStateTests(TestCase):
    """
    Glue ``UnblindedTokenStateTests`` into our test runner.
    """

    def test_states(self) -> None:
        run_state_machine_as_test(lambda: UnblindedTokenStateMachine(self))


class LeaseMaintenanceTests(TestCase):
    """
    Tests for the lease-maintenance related parts of ``VoucherStore``.
    """

    @given(
        tahoe_configs(),
        posix_safe_datetimes(),
        lists(
            tuples(
                # How much time passes before this activity starts
                timedeltas(min_value=timedelta(1), max_value=timedelta(days=1)),
                # Some activity.  This list of two tuples gives us a trivial
                # way to compute the total passes required (just sum the pass
                # counts in it).  This is nice because it avoids having the
                # test re-implement size quantization which would just be
                # repeated code duplicating the implementation.  The second
                # value lets us fuzz the actual size values a little bit in a
                # way which shouldn't affect the passes required.
                lists(
                    tuples(
                        # The activity itself, in pass count
                        integers(min_value=1, max_value=2**16 - 1),
                        # Amount by which to trim back the share sizes.  This
                        # might exceed the value of a single pass but we don't
                        # know that value yet.  We'll map it into a coherent
                        # range with mod inside the test.
                        integers(min_value=0),
                    ),
                ),
                # How much time passes before this activity finishes
                timedeltas(min_value=timedelta(1), max_value=timedelta(days=1)),
            ),
        ),
    )
    def test_lease_maintenance_activity(self, get_config, now, activity) -> None:
        """
        ``VoucherStore.get_latest_lease_maintenance_activity`` returns a
        ``LeaseMaintenanceTests`` with fields reflecting the most recently
        finished lease maintenance activity.
        """
        store = self.useFixture(
            TemporaryVoucherStore(lambda: now, get_config),
        ).store

        expected = None
        for (start_delay, sizes, finish_delay) in activity:
            now += start_delay
            started = now
            x = store.start_lease_maintenance()
            passes_required = 0
            for (num_passes, trim_size) in sizes:
                passes_required += num_passes
                trim_size %= store.pass_value
                x.observe(
                    [
                        num_passes * store.pass_value - trim_size,
                    ]
                )
            now += finish_delay
            x.finish()
            finished = now

            # Let the last iteration of the loop define the expected value.
            expected = LeaseMaintenanceActivity(
                started,
                passes_required,
                finished,
            )

        self.assertThat(
            store.get_latest_lease_maintenance_activity(),
            Equals(expected),
        )


class EventStreamTests(TestCase):
    """
    Tests related to the event-stream storage of VoucherStore
    """

    # Hypothesis can't auto-build EventStream because the module uses
    # __future__.annotations. :(
    @given(
        builds(
            EventStream,
            lists(
                builds(
                    Change,
                    integers(),
                    text(),
                    lists(sql_values()),
                    booleans(),
                ),
            ),
        ),
    )
    def test_roundtrip_through_bytes(self, eventstream) -> None:
        """
        ``EventStream`` instances round-trip through ``to_bytes`` and
        ``from_bytes``.
        """
        reloaded = EventStream.from_bytes(eventstream.to_bytes())
        self.assertThat(reloaded, Equals(eventstream))

    @given(
        tahoe_configs(),
        posix_safe_datetimes(),
        lists(sql_identifiers(), min_size=1),
        tables(),
        data(),
        lists(sampled_from([inserts, deletes, updates]), min_size=1),
    )
    def test_event_stream_serialization(
        self, get_config, now, ids, table, data, change_types
    ) -> None:
        """
        Various kinds of SQL statements can be serialized into and out of
        the event-stream.
        """
        store = self.useFixture(
            TemporaryVoucherStore(lambda: now, get_config),
        ).store

        # Generate some changes
        expected_changes = []
        sequence = count(1)
        for sql_id in ids:
            for change_type in change_types:
                change = data.draw(change_type(sql_id, table))
                expected_changes.append(
                    Change(
                        next(sequence),
                        change.statement(),
                        change.arguments(),
                        False,
                    )
                )
                with store._connection:
                    curse = store._connection.cursor()
                    add_events(curse, [(change.statement(), change.arguments())], False)

        # List comprehension has incompatible type List[Change]; expected List[_T_co]
        expected_stream = EventStream(expected_changes)  # type: ignore
        actual_changes = get_events(store._connection)
        self.assertThat(
            actual_changes,
            Equals(expected_stream),
        )
        # also ensure the serializer works
        self.assertThat(
            EventStream.from_bytes(actual_changes.to_bytes()),
            Equals(expected_stream),
        )
        self.assertThat(
            actual_changes.highest_sequence(),
            Equals(len(expected_changes)),
        )

    def test_event_stream_invalid_version(self) -> None:
        """
        An EventStream with an unknown version errors on deserialization
        """
        serialized = cbor2.dumps({"version": -1})
        self.assertThat(lambda: EventStream.from_bytes(serialized), raises(ValueError))

    @given(
        tahoe_configs(),
        posix_safe_datetimes(),
        lists(
            tuples(
                sampled_from([inserts, deletes, updates]),
                sql_identifiers(),
                tables(),
            ).flatmap(
                lambda x: x[0](x[1], x[2]),
            ),
            min_size=2,
        ),
        randoms(),
    )
    def test_event_stream_prune(self, get_config, now, changes, random) -> None:
        """
        After ``prune_events_to``, ``get_events`` only returns events events with
        a greater sequence number.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store

        with store._connection:
            curse = store._connection.cursor()
            add_events(
                curse,
                [(change.statement(), change.arguments()) for change in changes],
                False,
            )

        pre_events = get_events(store._connection)

        # prune it somewhere
        where = random.randrange(1, len(changes))
        prune_events_to(store._connection, where)

        post_events = get_events(store._connection)

        self.assertThat(
            post_events.changes,
            Equals(pre_events.changes[where:]),
        )


class VoucherTests(TestCase):
    """
    Tests for ``Voucher``.
    """

    @given(voucher_objects())
    def test_json_roundtrip(self, reference) -> None:
        """
        ``Voucher.to_json . Voucher.from_json → id``
        """
        self.assertThat(
            Voucher.from_json(reference.to_json()),
            Equals(reference),
        )


def paired_tokens(num_tokens=integers(min_value=1, max_value=1000)):
    """
    Build tuples of two lists of the same length, one of random tokens and one
    of unblinded tokens.

    :rtype: ([RandomTokens], [UnblindedTokens])
    """

    def pairs(num):
        return tuples(
            lists(
                random_tokens(),
                min_size=num,
                max_size=num,
                unique=True,
            ),
            lists(
                unblinded_tokens(),
                min_size=num,
                max_size=num,
                unique=True,
            ),
        )

    return num_tokens.flatmap(pairs)


class UnblindedTokenStoreTests(TestCase):
    """
    Tests for ``UnblindedToken``-related functionality of ``VoucherStore``.
    """

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        lists(unblinded_tokens(), unique=True),
        booleans(),
    )
    def test_unblinded_tokens_without_voucher(
        self, get_config, now, voucher_value, public_key, unblinded_tokens, completed
    ) -> None:
        """
        Unblinded tokens for a voucher which has not been added to the store cannot be inserted.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        self.assertThat(
            lambda: store.insert_unblinded_tokens_for_voucher(
                voucher_value,
                public_key,
                unblinded_tokens,
                completed,
                spendable=True,
            ),
            raises(ValueError),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        booleans(),
        paired_tokens(),
    )
    def test_unblinded_tokens_round_trip(
        self, get_config, now, voucher_value, public_key, completed, tokens
    ) -> None:
        """
        Unblinded tokens that are added to the store can later be retrieved and counted.
        """
        random_tokens, unblinded_tokens = tokens
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        store.add(voucher_value, len(random_tokens), 0, lambda: random_tokens)
        store.insert_unblinded_tokens_for_voucher(
            voucher_value, public_key, unblinded_tokens, completed, spendable=True
        )

        # All the tokens just inserted should be counted.
        self.expectThat(
            store.count_unblinded_tokens(),
            Equals(len(unblinded_tokens)),
        )
        retrieved_tokens = store.get_unblinded_tokens(len(random_tokens))

        # All the tokens just extracted should not be counted.
        self.expectThat(
            store.count_unblinded_tokens(),
            Equals(0),
        )

        self.expectThat(
            set(unblinded_tokens),
            Equals(set(retrieved_tokens)),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        paired_tokens(),
    )
    def test_mark_vouchers_redeemed(
        self, get_config, now, voucher_value, public_key, tokens
    ) -> None:
        """
        The voucher for unblinded tokens that are added to the store is marked as
        redeemed.
        """
        random, unblinded = tokens
        num_tokens = len(random)
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        store.add(voucher_value, len(random), 0, lambda: random)
        store.insert_unblinded_tokens_for_voucher(
            voucher_value, public_key, unblinded, completed=True, spendable=True
        )
        loaded_voucher = store.get(voucher_value)
        self.assertThat(
            loaded_voucher,
            MatchesStructure(
                expected_tokens=Equals(len(random)),
                state=Equals(
                    Redeemed(
                        finished=now,
                        token_count=num_tokens,
                    )
                ),
            ),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
        lists(random_tokens(), min_size=1, unique=True),
    )
    def test_mark_vouchers_double_spent(
        self, get_config, now, voucher_value, random_tokens
    ) -> None:
        """
        A voucher which is reported as double-spent is marked in the database as
        such.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        store.add(voucher_value, len(random_tokens), 0, lambda: random_tokens)
        store.mark_voucher_double_spent(voucher_value)
        voucher = store.get(voucher_value)
        self.assertThat(
            voucher,
            MatchesStructure(
                state=Equals(
                    DoubleSpend(
                        finished=now,
                    )
                ),
            ),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        paired_tokens(),
    )
    def test_mark_spent_vouchers_double_spent(
        self, get_config, now, voucher_value, public_key, tokens
    ) -> None:
        """
        A voucher which has already been spent cannot be marked as double-spent.
        """
        random, unblinded = tokens
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        store.add(voucher_value, len(random), 0, lambda: random)
        store.insert_unblinded_tokens_for_voucher(
            voucher_value, public_key, unblinded, completed=True, spendable=True
        )
        self.assertThat(
            lambda: store.mark_voucher_double_spent(voucher_value),
            raises(ValueError),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
    )
    def test_mark_invalid_vouchers_double_spent(
        self, get_config, now, voucher_value
    ) -> None:
        """
        A voucher which is not known cannot be marked as double-spent.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        self.assertThat(
            lambda: store.mark_voucher_double_spent(voucher_value),
            raises(ValueError),
        )

    @given(
        get_config=tahoe_configs(),
        now=aware_datetimes(),
        voucher_value=vouchers(),
        public_key=dummy_ristretto_keys(),
        completed=booleans(),
        extra_bits=integers(min_value=1, max_value=128),
        extra_fuzz=integers(min_value=1),
        tokens=paired_tokens(),
    )
    def test_not_enough_unblinded_tokens(
        self,
        get_config,
        now,
        voucher_value,
        public_key,
        completed,
        extra_bits,
        extra_fuzz,
        tokens,
    ) -> None:
        """
        ``get_unblinded_tokens`` raises ``NotEnoughTokens`` if ``count`` is
        greater than the number of unblinded tokens in the store.
        """
        random, unblinded = tokens
        num_tokens = len(random)
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        store.add(voucher_value, len(random), 0, lambda: random)
        store.insert_unblinded_tokens_for_voucher(
            voucher_value,
            public_key,
            unblinded,
            completed,
            spendable=True,
        )
        # Compute a number of "extra" tokens to request -- tokens that won't
        # be available -- in a way that tries to distribute that number across
        # a very large range.  We know that the implementation has a boundary
        # around 2 ** 63 and using a simple integers() strategy for extra,
        # Hypothesis usually tries examples on both sides of that boundary -
        # but not always.  *Most* of the numbers between 1 and 2 ** 63 are
        # invalid in exactly the same way (as far as I know) but I'd still
        # like to try them out a bit.
        #
        # Better factoring for this would probably be to have a
        # exponential_integers() strategy... Maybe?
        extra = 2**extra_bits
        extra += extra_fuzz % extra
        self.assertThat(
            lambda: store.get_unblinded_tokens(num_tokens + extra),
            raises(NotEnoughTokens),
        )


class PassTests(TestCase):
    """
    Tests for ``Pass``.
    """

    @given(zkaps())
    def test_roundtrip(self, pass_) -> None:
        """
        ``Pass`` round-trips through ``Pass.from_bytes`` and ``Pass.pass_bytes``.
        """
        self.assertThat(
            Pass.from_bytes(pass_.pass_bytes),
            Equals(pass_),
        )


class ReplicationTests(TestCase):
    """
    Tests for replication and recovery - especially tests for successful
    integration of different pieces that go into those processes.
    """

    def test_recover(self) -> None:
        """
        Given a snapshot returned by ``snapshot`` can be loaded into an empty
        ``VoucherStore`` using ``VoucherStore.call_if_empty`` with
        ``StatefulRecoverer.recover``.
        """
        store = self.useFixture(
            TemporaryVoucherStore(
                # Time is not relevant to this test
                get_now=aware_now,
            )
        ).store
        snapshot_bytes = store.snapshot()
        downloader = make_canned_downloader(snapshot_bytes, [])
        recoverer = StatefulRecoverer()

        # StatefulRecoverer.recover should always succeed.  Verify that.
        self.assertThat(
            Deferred.fromCoroutine(
                store.call_if_empty(partial(recoverer.recover, downloader))
            ),
            succeeded(Always()),
        )

        # It is not enough for StatefulRecoverer.recover to succeed, though.
        # StatefulRecoverer must also end up in the succeeded state.
        self.assertThat(
            recoverer.state(),
            Equals(
                RecoveryState(
                    stage=RecoveryStages.succeeded,
                ),
            ),
        )


class MemoryConnectTests(TestCase):
    """
    Tests for ``memory_connect``.
    """

    def test_shared(self) -> None:
        """
        ``memory_connect`` returns connections to the same database when passed
        the same path.
        """
        path = self.useFixture(TempDir()).join("db.sqlite3")
        first = memory_connect(path)
        second = memory_connect(path)

        with first:
            cursor = first.cursor()
            cursor.execute("CREATE TABLE foo ( a INT )")
            cursor.execute("INSERT INTO foo VALUES (?)", (1,))

        with second:
            cursor = second.cursor()
            cursor.execute("SELECT a FROM foo")
            rows = cursor.fetchall()

        self.assertThat(rows, Equals([(1,)]))

    def test_distinct(self) -> None:
        """
        ``memory_connect`` returns connections to different databases when passed
        different paths.
        """
        first_path = self.useFixture(TempDir()).join("db.sqlite3")
        first = memory_connect(first_path)
        second_path = self.useFixture(TempDir()).join("db.sqlite3")
        second = memory_connect(second_path)

        with first:
            cursor = first.cursor()
            cursor.execute("CREATE TABLE foo ( a INT )")
            cursor.execute("INSERT INTO foo VALUES (?)", (1,))

        with second:
            cursor = second.cursor()
            self.assertThat(
                partial(cursor.execute, "SELECT a FROM foo"),
                raises(OperationalError),
            )
