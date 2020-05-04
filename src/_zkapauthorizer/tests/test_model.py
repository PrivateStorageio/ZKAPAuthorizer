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

from __future__ import (
    absolute_import,
)

from os import (
    mkdir,
)
from errno import (
    EACCES,
)
from datetime import (
    timedelta,
)

from unittest import (
    skipIf,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    AfterPreprocessing,
    MatchesStructure,
    MatchesAll,
    Equals,
    Raises,
    IsInstance,
)

from fixtures import (
    TempDir,
)

from hypothesis import (
    given,
)

from hypothesis.strategies import (
    data,
    lists,
    tuples,
    datetimes,
    timedeltas,
    integers,
)

from twisted.python.runtime import (
    platform,
)

from ..model import (
    StoreOpenError,
    NotEnoughTokens,
    VoucherStore,
    Voucher,
    Pending,
    DoubleSpend,
    Redeemed,
    LeaseMaintenanceActivity,
    memory_connect,
)

from .strategies import (
    tahoe_configs,
    vouchers,
    voucher_objects,
    random_tokens,
    unblinded_tokens,
    posix_safe_datetimes,
    dummy_ristretto_keys,
)
from .fixtures import (
    TemporaryVoucherStore,
)
from .matchers import (
    raises,
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

    @given(tahoe_configs(), vouchers(), lists(random_tokens(), unique=True), datetimes())
    def test_add(self, get_config, voucher, tokens, now):
        """
        ``VoucherStore.get`` returns a ``Voucher`` representing a voucher
        previously added to the store with ``VoucherStore.add``.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        store.add(voucher, lambda: tokens)
        self.assertThat(
            store.get(voucher),
            MatchesStructure(
                number=Equals(voucher),
                state=Equals(Pending(counter=0)),
                created=Equals(now),
            ),
        )

    @given(tahoe_configs(), vouchers(), datetimes(), lists(random_tokens(), unique=True))
    def test_add_idempotent(self, get_config, voucher, now, tokens):
        """
        More than one call to ``VoucherStore.add`` with the same argument results
        in the same state as a single call.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        first_tokens = store.add(voucher, lambda: tokens)
        second_tokens = store.add(voucher, lambda: [])
        self.assertThat(
            store.get(voucher),
            MatchesStructure(
                number=Equals(voucher),
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

    @given(tahoe_configs(), datetimes(), lists(vouchers(), unique=True))
    def test_list(self, get_config, now, vouchers):
        """
        ``VoucherStore.list`` returns a ``list`` containing a ``Voucher`` object
        for each voucher previously added.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        for voucher in vouchers:
            store.add(voucher, lambda: [])

        self.assertThat(
            store.list(),
            Equals(list(
                Voucher(number, created=now)
                for number
                in vouchers
            )),
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


    @skipIf(platform.isWindows(), "Hard to prevent database from being opened on Windows")
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
    def test_spend_order_equals_backup_order(self, get_config, voucher_value, public_key, now, data):
        """
        Unblinded tokens returned by ``VoucherStore.backup`` appear in the same
        order as they are returned ``VoucherStore.extract_unblinded_tokens``.
        """
        backed_up_tokens, spent_tokens, inserted_tokens = self._spend_order_test(
            get_config,
            voucher_value,
            public_key,
            now,
            data
        )
        self.assertThat(
            backed_up_tokens,
            Equals(spent_tokens),
        )


    @given(tahoe_configs(), vouchers(), dummy_ristretto_keys(), datetimes(), data())
    def test_spend_order_equals_insert_order(self, get_config, voucher_value, public_key, now, data):
        """
        Unblinded tokens returned by ``VoucherStore.extract_unblinded_tokens``
        appear in the same order as they were inserted.
        """
        backed_up_tokens, spent_tokens, inserted_tokens = self._spend_order_test(
            get_config,
            voucher_value,
            public_key,
            now,
            data
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
        :param unicode public_key: A public key to associate with inserted unblinded tokens.
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
        random_tokens, unblinded_tokens = paired_tokens(data, integers(min_value=1, max_value=5))
        store.add(voucher_value, lambda: random_tokens)
        store.insert_unblinded_tokens_for_voucher(
            voucher_value,
            public_key,
            unblinded_tokens,
        )

        backed_up_tokens = store.backup()[u"unblinded-tokens"]
        extracted_tokens = []
        tokens_remaining = len(unblinded_tokens)
        while tokens_remaining > 0:
            to_spend = data.draw(integers(min_value=1, max_value=tokens_remaining))
            extracted_tokens.extend(
                token.unblinded_token
                for token
                in store.extract_unblinded_tokens(to_spend)
            )
            tokens_remaining -= to_spend

        return (
            backed_up_tokens,
            extracted_tokens,
            list(token.unblinded_token for token in unblinded_tokens),
        )



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
                x.observe([
                    num_passes * store.pass_value - trim_size,
                ])
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
    r = data.draw(lists(
        random_tokens(),
        min_size=num_tokens,
        max_size=num_tokens,
        unique=True,
    ))
    u = data.draw(lists(
        unblinded_tokens(),
        min_size=num_tokens,
        max_size=num_tokens,
        unique=True,
    ))
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
    )
    def test_unblinded_tokens_without_voucher(self, get_config, now, voucher_value, public_key, unblinded_tokens):
        """
        Unblinded tokens for a voucher which has not been added to the store cannot be inserted.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        self.assertThat(
            lambda: store.insert_unblinded_tokens_for_voucher(
                voucher_value,
                public_key,
                unblinded_tokens,
            ),
            raises(ValueError),
        )

    @given(
        tahoe_configs(),
        datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        data(),
    )
    def test_unblinded_tokens_round_trip(self, get_config, now, voucher_value, public_key, data):
        """
        Unblinded tokens that are added to the store can later be retrieved.
        """
        random_tokens, unblinded_tokens = paired_tokens(data)
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        store.add(voucher_value, lambda: random_tokens)
        store.insert_unblinded_tokens_for_voucher(voucher_value, public_key, unblinded_tokens)
        retrieved_tokens = store.extract_unblinded_tokens(len(random_tokens))

        self.expectThat(
            set(unblinded_tokens),
            Equals(set(retrieved_tokens)),
        )

        # After extraction, the unblinded tokens are no longer available.
        self.assertThat(
            lambda: store.extract_unblinded_tokens(1),
            raises(NotEnoughTokens),
        )

    @given(
        tahoe_configs(),
        datetimes(),
        vouchers(),
        dummy_ristretto_keys(),
        integers(min_value=1, max_value=100),
        data(),
    )
    def test_mark_vouchers_redeemed(self, get_config, now, voucher_value, public_key, num_tokens, data):
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
        store.add(voucher_value, lambda: random)
        store.insert_unblinded_tokens_for_voucher(voucher_value, public_key, unblinded)
        loaded_voucher = store.get(voucher_value)
        self.assertThat(
            loaded_voucher,
            MatchesStructure(
                state=Equals(Redeemed(
                    finished=now,
                    token_count=num_tokens,
                    public_key=public_key,
                )),
            ),
        )

    @given(
        tahoe_configs(),
        datetimes(),
        vouchers(),
        lists(random_tokens(), unique=True),
    )
    def test_mark_vouchers_double_spent(self, get_config, now, voucher_value, random_tokens):
        """
        A voucher which is reported as double-spent is marked in the database as
        such.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        store.add(voucher_value, lambda: random_tokens)
        store.mark_voucher_double_spent(voucher_value)
        voucher = store.get(voucher_value)
        self.assertThat(
            voucher,
            MatchesStructure(
                state=Equals(DoubleSpend(
                    finished=now,
                )),
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
    def test_mark_spent_vouchers_double_spent(self, get_config, now, voucher_value, public_key, num_tokens, data):
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
        store.add(voucher_value, lambda: random)
        store.insert_unblinded_tokens_for_voucher(voucher_value, public_key, unblinded)
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
        integers(min_value=1, max_value=100),
        integers(min_value=1),
        data(),
    )
    def test_not_enough_unblinded_tokens(self, get_config, now, voucher_value, public_key, num_tokens, extra, data):
        """
        ``extract_unblinded_tokens`` raises ``NotEnoughTokens`` if ``count`` is
        greater than the number of unblinded tokens in the store.
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
        store.add(voucher_value, lambda: random)
        store.insert_unblinded_tokens_for_voucher(voucher_value, public_key, unblinded)

        self.assertThat(
            lambda: store.extract_unblinded_tokens(num_tokens + extra),
            raises(NotEnoughTokens),
        )


    # TODO: Other error states and transient states


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
