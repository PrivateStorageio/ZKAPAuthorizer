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

from __future__ import absolute_import

from datetime import datetime, timedelta
from errno import EACCES
from os import mkdir
from unittest import skipIf

from fixtures import TempDir
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
    data,
    datetimes,
    integers,
    lists,
    randoms,
    timedeltas,
    tuples,
)
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    Equals,
    HasLength,
    IsInstance,
    MatchesAll,
    MatchesStructure,
    Raises,
)
from testtools.twistedsupport import succeeded
from twisted.python.runtime import platform

from ..model import (
    DoubleSpend,
    LeaseMaintenanceActivity,
    NotEnoughTokens,
    Pending,
    Redeemed,
    StoreOpenError,
    Voucher,
    VoucherStore,
    memory_connect,
)
from .fixtures import ConfiglessMemoryVoucherStore, TemporaryVoucherStore
from .matchers import raises
from .strategies import (
    dummy_ristretto_keys,
    pass_counts,
    posix_safe_datetimes,
    random_tokens,
    tahoe_configs,
    unblinded_tokens,
    voucher_counters,
    voucher_objects,
    vouchers,
)


class VoucherStoreTests(TestCase):
    """
    Tests for ``VoucherStore``.
    """

    @given(tahoe_configs(), datetimes(), vouchers())
    def test_get_missing(self, get_config, now, voucher):
        """
        ``VoucherStore.get`` raises ``KeyError`` when called with a
        voucher not previously added to the store.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        self.assertThat(
            lambda: store.get(voucher),
            raises(KeyError),
        )

    @given(
        tahoe_configs(),
        vouchers(),
        lists(random_tokens(), min_size=1, unique=True),
        datetimes(),
    )
    def test_add(self, get_config, voucher, tokens, now):
        """
        ``VoucherStore.get`` returns a ``Voucher`` representing a voucher
        previously added to the store with ``VoucherStore.add``.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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
        datetimes(),
    )
    def test_add_with_distinct_counters(
        self, get_config, voucher, counters, tokens, now
    ):
        """
        ``VoucherStore.add`` adds new tokens to the store when passed the same
        voucher but a different counter value.
        """
        counter_a = counters[0]
        counter_b = counters[1]
        tokens_a = tokens[: len(tokens) / 2]
        tokens_b = tokens[len(tokens) / 2 :]

        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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
        datetimes(),
        lists(random_tokens(), min_size=1, unique=True),
    )
    def test_add_idempotent(self, get_config, voucher, now, tokens):
        """
        More than one call to ``VoucherStore.add`` with the same argument results
        in the same state as a single call.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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

    @given(tahoe_configs(), datetimes(), lists(vouchers(), unique=True), data())
    def test_list(self, get_config, now, vouchers, data):
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
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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

    @skipIf(platform.isWindows(), "Hard to prevent directory creation on Windows")
    @given(tahoe_configs(), datetimes())
    def test_uncreateable_store_directory(self, get_config, now):
        """
        If the underlying directory in the node configuration cannot be created
        then ``VoucherStore.from_node_config`` raises ``StoreOpenError``.
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")

        # Create the node directory without permission to create the
        # underlying directory.
        mkdir(nodedir, 0o500)

        config = get_config(nodedir, b"tub.port")

        self.assertThat(
            lambda: VoucherStore.from_node_config(
                config,
                lambda: now,
                memory_connect,
            ),
            Raises(
                AfterPreprocessing(
                    lambda (type, exc, tb): exc,
                    MatchesAll(
                        IsInstance(StoreOpenError),
                        MatchesStructure(
                            reason=MatchesAll(
                                IsInstance(OSError),
                                MatchesStructure(
                                    errno=Equals(EACCES),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

    @skipIf(
        platform.isWindows(), "Hard to prevent database from being opened on Windows"
    )
    @given(tahoe_configs(), datetimes())
    def test_unopenable_store(self, get_config, now):
        """
        If the underlying database file cannot be opened then
        ``VoucherStore.from_node_config`` raises ``StoreOpenError``.
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")

        config = get_config(nodedir, b"tub.port")

        # Create the underlying database file.
        store = VoucherStore.from_node_config(config, lambda: now)

        # Prevent further access to it.
        store.database_path.chmod(0o000)

        self.assertThat(
            lambda: VoucherStore.from_node_config(
                config,
                lambda: now,
            ),
            raises(StoreOpenError),
        )

    @given(tahoe_configs(), vouchers(), dummy_ristretto_keys(), datetimes(), data())
    def test_spend_order_equals_backup_order(
        self, get_config, voucher_value, public_key, now, data
    ):
        """
        Unblinded tokens returned by ``VoucherStore.backup`` appear in the same
        order as they are returned by ``VoucherStore.get_unblinded_tokens``.
        """
        backed_up_tokens, spent_tokens, inserted_tokens = self._spend_order_test(
            get_config, voucher_value, public_key, now, data
        )
        self.assertThat(
            backed_up_tokens,
            Equals(spent_tokens),
        )

    @given(tahoe_configs(), vouchers(), dummy_ristretto_keys(), datetimes(), data())
    def test_spend_order_equals_insert_order(
        self, get_config, voucher_value, public_key, now, data
    ):
        """
        Unblinded tokens returned by ``VoucherStore.get_unblinded_tokens``
        appear in the same order as they were inserted.
        """
        backed_up_tokens, spent_tokens, inserted_tokens = self._spend_order_test(
            get_config, voucher_value, public_key, now, data
        )
        self.assertThat(
            spent_tokens,
            Equals(inserted_tokens),
        )

    def _spend_order_test(self, get_config, voucher_value, public_key, now, data):
        """
        Insert, backup, and extract some tokens.

        :param get_config: See ``tahoe_configs``
        :param unicode voucher_value: A voucher value to associate with the tokens.
        :param unicode public_key: A public key to associate with inserted
            unblinded tokens.
        :param datetime now: A time to pretend is current.
        :param data: A Hypothesis data for drawing values from strategies.

        :return: A three-tuple of (backed up tokens, extracted tokens, inserted tokens).
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")

        config = get_config(nodedir, b"tub.port")

        # Create the underlying database file.
        store = VoucherStore.from_node_config(config, lambda: now)

        # Put some tokens in it that we can backup and extract
        random_tokens, unblinded_tokens = paired_tokens(
            data, integers(min_value=1, max_value=5)
        )
        store.add(voucher_value, len(random_tokens), 0, lambda: random_tokens)
        store.insert_unblinded_tokens_for_voucher(
            voucher_value,
            public_key,
            unblinded_tokens,
            completed=data.draw(booleans()),
            spendable=True,
        )

        backed_up_tokens = store.backup()[u"unblinded-tokens"]
        extracted_tokens = []
        tokens_remaining = len(unblinded_tokens)
        while tokens_remaining > 0:
            to_spend = data.draw(integers(min_value=1, max_value=tokens_remaining))
            extracted_tokens.extend(
                token.unblinded_token for token in store.get_unblinded_tokens(to_spend)
            )
            tokens_remaining -= to_spend

        return (
            backed_up_tokens,
            extracted_tokens,
            list(token.unblinded_token for token in unblinded_tokens),
        )


class UnblindedTokenStateMachine(RuleBasedStateMachine):
    """
    Transition rules for a state machine corresponding to the state of
    unblinded tokens in a ``VoucherStore`` - usable, in-use, spent, invalid,
    etc.
    """

    def __init__(self, case):
        super(UnblindedTokenStateMachine, self).__init__()
        self.case = case
        self.configless = ConfiglessMemoryVoucherStore(
            # Time probably not actually relevant to this state machine.
            datetime.now,
        )
        self.configless.setUp()

        self.available = 0
        self.using = []
        self.spent = []
        self.invalid = []

    def teardown(self):
        self.configless.cleanUp()

    @rule(voucher=vouchers(), num_passes=pass_counts())
    def redeem_voucher(self, voucher, num_passes):
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

    @rule(num_passes=pass_counts())
    def get_passes(self, num_passes):
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
    def not_enough_passes(self, excess_passes):
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
    def spend_passes(self, random, data):
        """
        Some in-use passes can be discarded.
        """
        self.using, to_spend = random_slice(self.using, random, data)
        note("spend_passes: {}".format(to_spend))
        self.configless.store.discard_unblinded_tokens(to_spend)

    @precondition(lambda self: len(self.using) > 0)
    @rule(random=randoms(), data=data())
    def reset_passes(self, random, data):
        """
        Some in-use passes can be returned to not-in-use state.
        """
        self.using, to_reset = random_slice(self.using, random, data)
        note("reset_passes: {}".format(to_reset))
        self.configless.store.reset_unblinded_tokens(to_reset)
        self.available += len(to_reset)

    @precondition(lambda self: len(self.using) > 0)
    @rule(random=randoms(), data=data())
    def invalidate_passes(self, random, data):
        """
        Some in-use passes are unusable and should be set aside.
        """
        self.using, to_invalidate = random_slice(self.using, random, data)
        note("invalidate_passes: {}".format(to_invalidate))
        self.configless.store.invalidate_unblinded_tokens(
            u"reason",
            to_invalidate,
        )
        self.invalid.extend(to_invalidate)

    @rule()
    def discard_ephemeral_state(self):
        """
        Reset all state that cannot outlive a single process, simulating a
        restart.

        XXX We have to reach into the guts of ``VoucherStore`` to do this
        because we're using an in-memory database.  We can't just open a new
        ``VoucherStore``. :/ Perhaps we should use an on-disk database...  Or
        maybe this is a good argument for using an explicitly attached
        temporary database instead of the built-in ``temp`` database.
        """
        with self.configless.store._connection:
            self.configless.store._connection.execute(
                """
                DELETE FROM [in-use]
                """,
            )
        self.available += len(self.using)
        del self.using[:]

    @invariant()
    def report_state(self):
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

    def test_states(self):
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
                        integers(min_value=1, max_value=2 ** 16 - 1),
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
    def test_lease_maintenance_activity(self, get_config, now, activity):
        """
        ``VoucherStore.get_latest_lease_maintenance_activity`` returns a
        ``LeaseMaintenanceTests`` with fields reflecting the most recently
        finished lease maintenance activity.
        """
        store = self.useFixture(
            TemporaryVoucherStore(get_config, lambda: now),
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


class VoucherTests(TestCase):
    """
    Tests for ``Voucher``.
    """

    @given(voucher_objects())
    def test_json_roundtrip(self, reference):
        """
        ``Voucher.to_json . Voucher.from_json → id``
        """
        self.assertThat(
            Voucher.from_json(reference.to_json()),
            Equals(reference),
        )


def paired_tokens(data, sizes=integers(min_value=1, max_value=1000)):
    """
    Draw two lists of the same length, one of random tokens and one of
    unblinded tokens.

    :rtype: ([RandomTokens], [UnblindedTokens])
    """
    num_tokens = data.draw(sizes)
    r = data.draw(
        lists(
            random_tokens(),
            min_size=num_tokens,
            max_size=num_tokens,
            unique=True,
        )
    )
    u = data.draw(
        lists(
            unblinded_tokens(),
            min_size=num_tokens,
            max_size=num_tokens,
            unique=True,
        )
    )
    return r, u


class UnblindedTokenStoreTests(TestCase):
    """
    Tests for ``UnblindedToken``-related functionality of ``VoucherStore``.
    """

    @given(
        tahoe_configs(),
        datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        lists(unblinded_tokens(), unique=True),
        booleans(),
    )
    def test_unblinded_tokens_without_voucher(
        self, get_config, now, voucher_value, public_key, unblinded_tokens, completed
    ):
        """
        Unblinded tokens for a voucher which has not been added to the store
        cannot be inserted.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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
        datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        booleans(),
        data(),
    )
    def test_unblinded_tokens_round_trip(
        self, get_config, now, voucher_value, public_key, completed, data
    ):
        """
        Unblinded tokens that are added to the store can later be retrieved and counted.
        """
        random_tokens, unblinded_tokens = paired_tokens(data)
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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
        datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        integers(min_value=1, max_value=100),
        data(),
    )
    def test_mark_vouchers_redeemed(
        self, get_config, now, voucher_value, public_key, num_tokens, data
    ):
        """
        The voucher for unblinded tokens that are added to the store is marked as
        redeemed.
        """
        random = data.draw(
            lists(
                random_tokens(),
                min_size=num_tokens,
                max_size=num_tokens,
                unique=True,
            ),
        )
        unblinded = data.draw(
            lists(
                unblinded_tokens(),
                min_size=num_tokens,
                max_size=num_tokens,
                unique=True,
            ),
        )

        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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
        datetimes(),
        vouchers(),
        lists(random_tokens(), min_size=1, unique=True),
    )
    def test_mark_vouchers_double_spent(
        self, get_config, now, voucher_value, random_tokens
    ):
        """
        A voucher which is reported as double-spent is marked in the database as
        such.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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
        datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        integers(min_value=1, max_value=100),
        data(),
    )
    def test_mark_spent_vouchers_double_spent(
        self, get_config, now, voucher_value, public_key, num_tokens, data
    ):
        """
        A voucher which has already been spent cannot be marked as double-spent.
        """
        random = data.draw(
            lists(
                random_tokens(),
                min_size=num_tokens,
                max_size=num_tokens,
                unique=True,
            ),
        )
        unblinded = data.draw(
            lists(
                unblinded_tokens(),
                min_size=num_tokens,
                max_size=num_tokens,
                unique=True,
            ),
        )
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
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
        datetimes(),
        vouchers(),
    )
    def test_mark_invalid_vouchers_double_spent(self, get_config, now, voucher_value):
        """
        A voucher which is not known cannot be marked as double-spent.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        self.assertThat(
            lambda: store.mark_voucher_double_spent(voucher_value),
            raises(ValueError),
        )

    @given(
        tahoe_configs(),
        datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        booleans(),
        integers(min_value=1),
        data(),
    )
    def test_not_enough_unblinded_tokens(
        self, get_config, now, voucher_value, public_key, completed, extra, data
    ):
        """
        ``get_unblinded_tokens`` raises ``NotEnoughTokens`` if ``count`` is
        greater than the number of unblinded tokens in the store.
        """
        random, unblinded = paired_tokens(data)
        num_tokens = len(random)
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        store.add(voucher_value, len(random), 0, lambda: random)
        store.insert_unblinded_tokens_for_voucher(
            voucher_value,
            public_key,
            unblinded,
            completed,
            spendable=True,
        )
        self.assertThat(
            lambda: store.get_unblinded_tokens(num_tokens + extra),
            raises(NotEnoughTokens),
        )


def store_for_test(testcase, get_config, get_now):
    """
    Create a ``VoucherStore`` in a temporary directory associated with the
    given test case.

    :param TestCase testcase: The test case for which to build the store.
    :param get_config: A function like the one built by ``tahoe_configs``.
    :param get_now: A no-argument callable that returns a datetime giving a
        time to consider as "now".

    :return VoucherStore: A newly created temporary store.
    """
    tempdir = testcase.useFixture(TempDir())
    config = get_config(tempdir.join(b"node"), b"tub.port")
    store = VoucherStore.from_node_config(
        config,
        get_now,
        memory_connect,
    )
    return store
