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
Tests for ``_zkapauthorizer._storage_server``.
"""

from random import shuffle
from time import time

from allmydata.interfaces import NoSpace
from allmydata.storage.mutable import MutableShareFile
from challenge_bypass_ristretto import PublicKey, random_signing_key
from foolscap.referenceable import LocalReferenceable
from hypothesis import given, note
from hypothesis.strategies import integers, just, lists, one_of, tuples
from testtools import TestCase
from testtools.matchers import AfterPreprocessing, Equals, MatchesAll
from twisted.internet.task import Clock
from twisted.python.runtime import platform

from .._storage_server import NewLengthRejected, _ValidationResult
from ..api import MorePassesRequired, ZKAPAuthorizerStorageServer
from ..server.spending import RecordingSpender
from ..storage_common import (
    add_lease_message,
    allocate_buckets_message,
    get_implied_data_length,
    get_required_new_passes_for_mutable_write,
    required_passes,
    slot_testv_and_readv_and_writev_message,
    summarize,
)
from .common import skipIf
from .fixtures import AnonymousStorageServer
from .matchers import matches_spent_passes, raises
from .storage_common import get_passes, reset_storage_server, write_toy_shares
from .strategies import (
    lease_cancel_secrets,
    lease_renew_secrets,
    sharenum_sets,
    sizes,
    slot_test_and_write_vectors_for_shares,
    storage_indexes,
    write_enabler_secrets,
    zkaps,
)


def _encode_passes(passes):
    """
    :return list[bytes]: The encoded form of the passes in the given group.
    """
    return list(t.pass_bytes for t in passes)


class ValidationResultTests(TestCase):
    """
    Tests for ``_ValidationResult``.
    """

    def setUp(self):
        super(ValidationResultTests, self).setUp()
        self.signing_key = random_signing_key()

    @given(integers(min_value=0, max_value=64), lists(zkaps(), max_size=64))
    def test_validation_result(self, valid_count, invalid_passes):
        """
        ``validate_passes`` returns a ``_ValidationResult`` instance which
        describes the valid and invalid passes.
        """
        message = b"hello world"
        valid_passes = get_passes(
            message,
            valid_count,
            self.signing_key,
        )
        all_passes = valid_passes + invalid_passes
        shuffle(all_passes)

        self.assertThat(
            _ValidationResult.validate_passes(
                message,
                _encode_passes(all_passes),
                self.signing_key,
            ),
            Equals(
                _ValidationResult(
                    valid=[
                        pass_.preimage for pass_ in all_passes if pass_ in valid_passes
                    ],
                    signature_check_failed=list(
                        idx
                        for (idx, pass_) in enumerate(all_passes)
                        if pass_ not in valid_passes
                    ),
                ),
            ),
        )

    def test_raise_for(self):
        """
        ``_ValidationResult.raise_for`` raises ``MorePassesRequired`` populated
        with details of the validation and how it fell short of what was
        required.
        """
        good = [0, 1, 2, 3]
        badsig = [4]
        required = 10
        result = _ValidationResult(good, badsig)
        try:
            result.raise_for(required)
        except MorePassesRequired as exc:
            self.assertThat(
                exc,
                MatchesAll(
                    Equals(
                        MorePassesRequired(
                            len(good),
                            required,
                            set(badsig),
                        ),
                    ),
                    AfterPreprocessing(
                        str,
                        Equals(
                            "MorePassesRequired(valid_count=4, required_count=10, signature_check_failed=frozenset({4}))",
                        ),
                    ),
                ),
            )


def read_spending_success_histogram_total(
    storage_server: ZKAPAuthorizerStorageServer,
) -> int:
    """
    Read the total number of values across all buckets of the spending success
    metric histogram.
    """
    # Reading _buckets seems like the least bad option for now.  See
    # https://github.com/prometheus/client_python/issues/736 though.
    buckets = storage_server._metric_spending_successes._buckets
    return sum(b.get() for b in buckets)


def read_spending_success_histogram_bucket(
    storage_server: ZKAPAuthorizerStorageServer, num_passes: int
) -> int:
    """
    Read the value of a single bucket of the spending success metric
    histogram.

    :param num_passes: A pass spending count which determines which bucket to
        read.  Whichever bucket holds values for the quantized pass count is
        the bucket to be read.
    """
    bounds = storage_server._get_spending_histogram_buckets()
    for bucket_number, upper_bound in enumerate(bounds):
        if num_passes <= upper_bound:
            break

    note("bucket_number {}".format(bucket_number))
    # See note above about reading private _buckets attribute.
    buckets = storage_server._metric_spending_successes._buckets
    note(
        "bucket counters: {}".format(list((n, b.get()) for n, b in enumerate(buckets)))
    )
    return buckets[bucket_number].get()


class PassValidationTests(TestCase):
    """
    Tests for pass validation performed by ``ZKAPAuthorizerStorageServer``.
    """

    pass_value = 128 * 1024

    @skipIf(platform.isWindows(), "Storage server is not supported on Windows")
    def setUp(self):
        super(PassValidationTests, self).setUp()
        self.clock = Clock()
        self.spending_recorder, spender = RecordingSpender.make()
        # anonymous_storage_server uses time.time() so get our Clock close to
        # the same time so we can do lease expiration calculations more
        # easily.
        self.clock.advance(time())
        self.anonymous_storage_server = self.useFixture(
            AnonymousStorageServer(self.clock),
        ).storage_server
        self.signing_key = random_signing_key()
        self.public_key_hash = PublicKey.from_signing_key(
            self.signing_key
        ).encode_base64()
        self.storage_server = ZKAPAuthorizerStorageServer(
            self.anonymous_storage_server,
            self.pass_value,
            self.signing_key,
            spender,
            clock=self.clock,
        )

    def setup_example(self):
        """
        Prepare the TestCase to run one example of one test.
        """
        # The storage server accumulates shares through the course of running
        # a single example.  Since existing state can invalidate assumptions
        # made by the tests, get rid of it.
        #
        # It might be nice to just create a new, empty storage server here
        # instead of cleaning up the old one.  For now, that's hard because
        # Hypothesis and testtools fixtures don't play nicely together in a
        # way that allows us to just move everything from `setUp` into this
        # method.
        reset_storage_server(self.anonymous_storage_server)

        self.spending_recorder.reset()

        # Reset all of the metrics, too, so the individual tests have a
        # simpler job (can compare values relative to 0).
        self.storage_server._clear_metrics()

    def test_allocate_buckets_fails_without_enough_passes(self):
        """
        ``remote_allocate_buckets`` fails with ``MorePassesRequired`` if it is
        passed fewer passes than it requires for the amount of data to be
        stored.
        """
        required_passes = 2
        share_nums = {3, 7}
        allocated_size = int((required_passes * self.pass_value) / len(share_nums))
        storage_index = b"0123456789"
        renew_secret = b"x" * 32
        cancel_secret = b"y" * 32
        valid_passes = get_passes(
            allocate_buckets_message(storage_index),
            required_passes - 1,
            self.signing_key,
        )

        allocate_buckets = lambda: self.storage_server.doRemoteCall(
            "allocate_buckets",
            (
                _encode_passes(valid_passes),
                storage_index,
                renew_secret,
                cancel_secret,
                share_nums,
                allocated_size,
                LocalReferenceable(None),
            ),
            {},
        )
        self.expectThat(self.spending_recorder.spent_tokens, Equals({}))
        self.assertThat(
            allocate_buckets,
            raises(MorePassesRequired),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
    )
    def test_create_mutable_fails_without_passes(self, storage_index, secrets):
        """
        If ``remote_slot_testv_and_readv_and_writev`` is invoked to perform
        initial writes on shares without supplying passes, the operation fails
        with ``MorePassesRequired``.
        """
        data = b"01234567"
        offset = 0
        sharenum = 0
        mutable_write = lambda: self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=[],
                storage_index=storage_index,
                secrets=secrets,
                tw_vectors={
                    sharenum: ([], [(offset, data)], None),
                },
                r_vector=[],
            ),
        )

        try:
            result = mutable_write()
        except MorePassesRequired as e:
            self.expectThat(self.spending_recorder.spent_tokens, Equals({}))
            self.assertThat(
                e,
                Equals(
                    MorePassesRequired(
                        valid_count=0,
                        required_count=1,
                        signature_check_failed=[],
                    ),
                ),
            )
        else:
            self.fail("expected MorePassesRequired, got {}".format(result))

    def _test_extend_mutable_fails_without_passes(
        self,
        storage_index,
        secrets,
        test_and_write_vectors_for_shares,
        make_data_vector,
    ):
        """
        Verify that increasing the storage requirements of a slot without
        supplying more passes fails.

        :param make_data_vector: A one-argument callable.  It will be called
            with the current length of a slot share.  It should return a write
            vector which will increase the storage requirements of that slot
            share by at least ``self.pass_value``.
        """
        tw_vectors = {
            k: v.for_call() for (k, v) in test_and_write_vectors_for_shares.items()
        }

        note("tw_vectors summarized: {}".format(summarize(tw_vectors)))

        # print("test suite")
        required_pass_count = get_required_new_passes_for_mutable_write(
            self.pass_value,
            dict.fromkeys(tw_vectors.keys(), 0),
            tw_vectors,
        )

        valid_passes = get_passes(
            slot_testv_and_readv_and_writev_message(storage_index),
            required_pass_count,
            self.signing_key,
        )

        # Create an initial share to toy with.
        test, read = self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=_encode_passes(valid_passes),
                storage_index=storage_index,
                secrets=secrets,
                tw_vectors=tw_vectors,
                r_vector=[],
            ),
        )
        self.assertThat(
            test,
            Equals(True),
            "Server denied initial write.",
        )

        self.assertThat(
            self.spending_recorder,
            matches_spent_passes(self.public_key_hash, valid_passes),
        )

        # Pick any share to make larger.
        sharenum = next(iter(tw_vectors))
        _, data_vector, new_length = tw_vectors[sharenum]
        current_length = get_implied_data_length(data_vector, new_length)

        new_tw_vectors = {
            sharenum: make_data_vector(current_length),
        }

        note("new tw_vectors: {}".format(summarize(new_tw_vectors)))

        do_extend = lambda: self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=[],
                storage_index=storage_index,
                secrets=secrets,
                tw_vectors=new_tw_vectors,
                r_vector=[],
            ),
        )

        try:
            result = do_extend()
        except MorePassesRequired as e:
            self.assertThat(
                e,
                Equals(
                    MorePassesRequired(
                        valid_count=0,
                        required_count=1,
                        signature_check_failed=[],
                    ),
                ),
            )
        else:
            self.fail("expected MorePassesRequired, got {}".format(result))

        self.assertThat(
            self.spending_recorder,
            matches_spent_passes(self.public_key_hash, valid_passes),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
    )
    def test_extend_mutable_with_write_fails_without_passes(
        self, storage_index, secrets, test_and_write_vectors_for_shares
    ):
        """
        If ``remote_slot_testv_and_readv_and_writev`` is invoked to increase
        storage usage by performing a write past the end of a share without
        supplying passes, the operation fails with ``MorePassesRequired``.
        """
        return self._test_extend_mutable_fails_without_passes(
            storage_index,
            secrets,
            test_and_write_vectors_for_shares,
            lambda current_length: (
                [],
                [(current_length, "x" * self.pass_value)],
                None,
            ),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        sharenums=sharenum_sets(),
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
        new_length=integers(),
    )
    def test_mutable_new_length_rejected(
        self,
        storage_index,
        secrets,
        sharenums,
        test_and_write_vectors_for_shares,
        new_length,
    ):
        """
        If ``new_length`` is not ``None`` then ``slot_testv_and_readv_and_writev``
        rejects the operation.
        """
        tw_vectors = {
            k: v.for_call() for (k, v) in test_and_write_vectors_for_shares.items()
        }
        # Change some tw_vector to have a non-None new_length.
        sharenum, (testv, writev, ignored) = tw_vectors.popitem()
        tw_vectors[sharenum] = (testv, writev, new_length)

        required_pass_count = get_required_new_passes_for_mutable_write(
            self.pass_value,
            dict.fromkeys(tw_vectors.keys(), 0),
            tw_vectors,
        )
        valid_passes = get_passes(
            slot_testv_and_readv_and_writev_message(storage_index),
            required_pass_count,
            self.signing_key,
        )

        # Try to do a write with the non-None new_length and expect it to be
        # rejected.
        try:
            result = self.storage_server.doRemoteCall(
                "slot_testv_and_readv_and_writev",
                (),
                dict(
                    passes=_encode_passes(valid_passes),
                    storage_index=storage_index,
                    secrets=secrets,
                    tw_vectors=tw_vectors,
                    r_vector=[],
                ),
            )
        except NewLengthRejected:
            pass
        else:
            self.fail("expected a failure but got {!r}".format(result))

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        sharenums=sharenum_sets(),
        allocated_size=sizes(),
    )
    def test_add_lease_fails_without_passes(
        self, storage_index, secrets, sharenums, allocated_size
    ):
        """
        If ``remote_add_lease`` is invoked without supplying enough passes to
        cover the storage for all shares on the given storage index, the
        operation fails with ``MorePassesRequired``.
        """
        renew_secret, cancel_secret = secrets

        required_count = required_passes(
            self.pass_value, [allocated_size] * len(sharenums)
        )
        # Create some shares at a slot which will require lease renewal.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            allocated_size,
        )

        # Advance time to a point where the lease is expired.  This simplifies
        # the logic behind how many passes will be required by the lease
        # operation (all of them).  If there is prorating for partially
        # expired leases then the calculation for a non-expired lease involves
        # more work.
        #
        # Add some slop here because time.time() is used by some parts of the
        # system. :/
        self.clock.advance(self.storage_server.LEASE_PERIOD.total_seconds() + 10.0)

        # Attempt the lease operation with one fewer pass than is required.
        passes = get_passes(
            add_lease_message(storage_index),
            required_count - 1,
            self.signing_key,
        )
        try:
            result = self.storage_server.doRemoteCall(
                "add_lease",
                (
                    _encode_passes(passes),
                    storage_index,
                    renew_secret,
                    cancel_secret,
                ),
                {},
            )
        except MorePassesRequired as e:
            self.assertThat(
                e,
                Equals(
                    MorePassesRequired(
                        valid_count=len(passes),
                        required_count=required_count,
                        signature_check_failed=[],
                    ),
                ),
            )
            # Since it was not successful, the successful spending metric
            # hasn't changed.
            self.assertThat(
                read_spending_success_histogram_total(self.storage_server),
                Equals(0),
            )
        else:
            self.fail("Expected MorePassesRequired, got {}".format(result))
        self.assertThat(self.spending_recorder.spent_tokens, Equals({}))

    @given(
        slot=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        sharenums=one_of(just(None), sharenum_sets()),
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
    )
    def test_mutable_share_sizes(
        self, slot, secrets, sharenums, test_and_write_vectors_for_shares
    ):
        """
        ``share_sizes`` returns the size of the requested mutable shares in the
        requested slot.
        """
        tw_vectors = {
            k: v.for_call() for (k, v) in test_and_write_vectors_for_shares.items()
        }

        # Create an initial share to toy with.
        required_pass_count = get_required_new_passes_for_mutable_write(
            self.pass_value,
            dict.fromkeys(tw_vectors.keys(), 0),
            tw_vectors,
        )
        valid_passes = get_passes(
            slot_testv_and_readv_and_writev_message(slot),
            required_pass_count,
            self.signing_key,
        )
        test, read = self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=_encode_passes(valid_passes),
                storage_index=slot,
                secrets=secrets,
                tw_vectors=tw_vectors,
                r_vector=[],
            ),
        )
        self.assertThat(
            test,
            Equals(True),
            "Server denied initial write.",
        )

        expected_sizes = {
            sharenum: get_implied_data_length(data_vector, new_length)
            for (sharenum, (testv, data_vector, new_length)) in tw_vectors.items()
            if sharenums is None or sharenum in sharenums
        }

        actual_sizes = self.storage_server.doRemoteCall(
            "share_sizes",
            (
                slot,
                sharenums,
            ),
            {},
        )
        self.assertThat(
            actual_sizes,
            Equals(expected_sizes),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
    )
    def test_mutable_spending_metrics(
        self,
        storage_index,
        secrets,
        test_and_write_vectors_for_shares,
    ):
        tw_vectors = {
            k: v.for_call() for (k, v) in test_and_write_vectors_for_shares.items()
        }
        num_passes = get_required_new_passes_for_mutable_write(
            self.pass_value,
            dict.fromkeys(tw_vectors.keys(), 0),
            tw_vectors,
        )
        valid_passes = get_passes(
            slot_testv_and_readv_and_writev_message(storage_index),
            num_passes,
            self.signing_key,
        )

        test, read = self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=_encode_passes(valid_passes),
                storage_index=storage_index,
                secrets=secrets,
                tw_vectors=tw_vectors,
                r_vector=[],
            ),
        )

        after_count = read_spending_success_histogram_total(self.storage_server)
        after_bucket = read_spending_success_histogram_bucket(
            self.storage_server, num_passes
        )

        self.expectThat(
            after_count,
            Equals(1),
            "Unexpected histogram sum value",
        )
        self.assertThat(
            after_bucket,
            Equals(1),
            "Unexpected histogram bucket value",
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
    )
    def test_mutable_failure_spending_metrics(
        self,
        storage_index,
        secrets,
        test_and_write_vectors_for_shares,
    ):
        """
        If a mutable storage operation fails then the successful pass spending
        metric is not incremented.
        """
        tw_vectors = {
            k: v.for_call() for (k, v) in test_and_write_vectors_for_shares.items()
        }
        num_passes = get_required_new_passes_for_mutable_write(
            self.pass_value,
            dict.fromkeys(tw_vectors.keys(), 0),
            tw_vectors,
        )
        valid_passes = get_passes(
            slot_testv_and_readv_and_writev_message(storage_index),
            num_passes,
            self.signing_key,
        )

        # The very last step of a mutable write is the lease renewal step.
        # We'll break that part to be sure metrics are only recorded after
        # that (ie, after the operation has completely succeeded).  It's not
        # easy to break that operation so we reach into some private guts to
        # do so...  After we upgrade to Tahoe 1.17.0 then we can mess around
        # with `reserved_space` to make Tahoe think there's no room for the
        # leases and fail the operation, perhaps (but how to do that without
        # making the earlier storage-allocating part of the operation fail?).
        self.patch(MutableShareFile, "add_or_renew_lease", lambda *a, **kw: 1 / 0)

        try:
            test, read = self.storage_server.doRemoteCall(
                "slot_testv_and_readv_and_writev",
                (),
                dict(
                    passes=_encode_passes(valid_passes),
                    storage_index=storage_index,
                    secrets=secrets,
                    tw_vectors=tw_vectors,
                    r_vector=[],
                ),
            )
        except ZeroDivisionError:
            pass
        else:
            self.fail("expected our ZeroDivisionError to be raised")

        after_count = read_spending_success_histogram_total(self.storage_server)
        self.expectThat(
            after_count,
            Equals(0),
            "Expected no successful spending to be recorded in error case",
        )

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        existing_sharenums=sharenum_sets(),
        new_sharenums=sharenum_sets(),
        size=sizes(),
    )
    def test_immutable_spending_metrics(
        self,
        storage_index,
        renew_secret,
        cancel_secret,
        existing_sharenums,
        new_sharenums,
        size,
    ):
        """
        When ZKAPs are spent to call *allocate_buckets* the number of passes spent
        is recorded as a metric.
        """
        # maybe create some existing shares that won't need to be paid for by
        # the subsequent `allocate_buckets` operation - but of which the
        # client is unaware.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            existing_sharenums,
            size,
        )

        # The client will present this many passes.
        num_passes = required_passes(self.pass_value, [size] * len(new_sharenums))
        # But only this many need to be spent.
        num_spent_passes = required_passes(
            self.pass_value,
            [size] * len(new_sharenums - existing_sharenums),
        )
        valid_passes = get_passes(
            allocate_buckets_message(storage_index),
            num_passes,
            self.signing_key,
        )

        alreadygot, allocated = self.storage_server.doRemoteCall(
            "allocate_buckets",
            (),
            dict(
                passes=_encode_passes(valid_passes),
                storage_index=storage_index,
                renew_secret=renew_secret,
                cancel_secret=cancel_secret,
                sharenums=new_sharenums,
                allocated_size=size,
                canary=LocalReferenceable(None),
            ),
        )

        after_count = read_spending_success_histogram_total(self.storage_server)
        after_bucket = read_spending_success_histogram_bucket(
            self.storage_server, num_spent_passes
        )

        self.expectThat(
            after_count,
            Equals(1),
            "Unexpected histogram sum value",
        )
        # If this bucket is 1 then all the other buckets must be 0, otherwise
        # the sum above will be greater than 1.
        self.assertThat(
            after_bucket,
            Equals(1),
            "Unexpected histogram bucket value",
        )

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenums=sharenum_sets(),
        allocated_size=sizes(),
    )
    def test_add_lease_metrics(
        self,
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        allocated_size,
    ):
        # Create some shares at a slot which will require lease renewal.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            allocated_size,
        )

        num_passes = required_passes(
            self.storage_server._pass_value, [allocated_size] * len(sharenums)
        )
        valid_passes = get_passes(
            add_lease_message(storage_index),
            num_passes,
            self.signing_key,
        )

        self.storage_server.doRemoteCall(
            "add_lease",
            (),
            dict(
                passes=_encode_passes(valid_passes),
                storage_index=storage_index,
                renew_secret=renew_secret,
                cancel_secret=cancel_secret,
            ),
        )

        after_count = read_spending_success_histogram_total(self.storage_server)
        after_bucket = read_spending_success_histogram_bucket(
            self.storage_server, num_passes
        )

        self.expectThat(
            after_count,
            Equals(1),
            "Unexpected histogram sum value",
        )
        self.assertThat(
            after_bucket,
            Equals(1),
            "Unexpected histogram bucket value",
        )

    @given(
        storage_index=storage_indexes(),
        renew_secrets=lists(lease_renew_secrets(), min_size=2, max_size=2, unique=True),
        cancel_secret=lease_cancel_secrets(),
        sharenums=sharenum_sets(),
        allocated_size=sizes(),
    )
    def test_add_lease_metrics_on_failure(
        self, storage_index, renew_secrets, cancel_secret, sharenums, allocated_size
    ):
        """
        If the ``add_lease`` operation fails then the successful pass spending
        metric is not incremented.
        """
        # We have two renew secrets so we can operate on two distinct leases.
        renew_secret, another_renew_secret = renew_secrets

        # Put some shares up there to target with the add_lease operation.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            allocated_size,
        )

        num_passes = required_passes(
            self.storage_server._pass_value, [allocated_size] * len(sharenums)
        )
        valid_passes = get_passes(
            add_lease_message(storage_index),
            num_passes,
            self.signing_key,
        )

        # Turn off space-allocating operations entirely.  Since there will be
        # no space for a new lease, the operation will fail.
        self.anonymous_storage_server.readonly_storage = True

        try:
            self.storage_server.doRemoteCall(
                "add_lease",
                (),
                dict(
                    passes=_encode_passes(valid_passes),
                    storage_index=storage_index,
                    renew_secret=another_renew_secret,
                    cancel_secret=cancel_secret,
                ),
            )
        except NoSpace:
            pass
        else:
            self.fail("expected NoSpace to be raised")

        after_count = read_spending_success_histogram_total(self.storage_server)
        self.expectThat(
            after_count,
            Equals(0),
            "Expected no successful spending to be recorded in error case",
        )
