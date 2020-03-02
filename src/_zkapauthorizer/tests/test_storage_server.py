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

from __future__ import (
    absolute_import,
    division,
)

from time import (
    time,
)
from random import (
    shuffle,
)
from testtools import (
    TestCase,
)
from testtools.matchers import (
    Equals,
    AfterPreprocessing,
    MatchesStructure,
    raises,
)
from hypothesis import (
    given,
    note,
)
from hypothesis.strategies import (
    integers,
    lists,
    tuples,
    one_of,
    just,
)
from privacypass import (
    RandomToken,
    random_signing_key,
)

from twisted.internet.task import (
    Clock,
)

from foolscap.referenceable import (
    LocalReferenceable,
)

from .privacypass import (
    make_passes,
)
from .strategies import (
    zkaps,
    sizes,
    sharenum_sets,
    storage_indexes,
    write_enabler_secrets,
    lease_renew_secrets,
    lease_cancel_secrets,
    test_and_write_vectors_for_shares,
)
from .fixtures import (
    AnonymousStorageServer,
)
from .storage_common import (
    cleanup_storage_server,
    write_toy_shares,
)
from ..api import (
    ZKAPAuthorizerStorageServer,
    MorePassesRequired,
)
from ..storage_common import (
    BYTES_PER_PASS,
    required_passes,
    allocate_buckets_message,
    add_lease_message,
    renew_lease_message,
    slot_testv_and_readv_and_writev_message,
    get_implied_data_length,
    get_required_new_passes_for_mutable_write,
    summarize,
)

class PassValidationTests(TestCase):
    """
    Tests for pass validation performed by ``ZKAPAuthorizerStorageServer``.
    """
    def setUp(self):
        super(PassValidationTests, self).setUp()
        self.clock = Clock()
        # anonymous_storage_server uses time.time() so get our Clock close to
        # the same time so we can do lease expiration calculations more
        # easily.
        self.clock.advance(time())
        self.anonymous_storage_server = self.useFixture(AnonymousStorageServer()).storage_server
        self.signing_key = random_signing_key()
        self.storage_server = ZKAPAuthorizerStorageServer(
            self.anonymous_storage_server,
            self.signing_key,
            self.clock,
        )

    @given(integers(min_value=0, max_value=64), lists(zkaps(), max_size=64))
    def test_validation_result(self, valid_count, invalid_passes):
        """
        ``_get_valid_passes`` returns the number of cryptographically valid passes
        in the list passed to it.
        """
        message = u"hello world"
        valid_passes = make_passes(
            self.signing_key,
            message,
            list(RandomToken.create() for i in range(valid_count)),
        )
        all_passes = valid_passes + list(
            pass_.pass_text.encode("ascii")
            for pass_
            in invalid_passes
        )
        shuffle(all_passes)

        self.assertThat(
            self.storage_server._validate_passes(message, all_passes),
            AfterPreprocessing(
                set,
                Equals(set(valid_passes)),
            ),
        )

    def test_allocate_buckets_fails_without_enough_passes(self):
        """
        ``remote_allocate_buckets`` fails with ``MorePassesRequired`` if it is
        passed fewer passes than it requires for the amount of data to be
        stored.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        required_passes = 2
        share_nums = {3, 7}
        allocated_size = int((required_passes * BYTES_PER_PASS) / len(share_nums))
        storage_index = b"0123456789"
        renew_secret = b"x" * 32
        cancel_secret = b"y" * 32
        valid_passes = make_passes(
            self.signing_key,
            allocate_buckets_message(storage_index),
            list(RandomToken.create() for i in range(required_passes - 1)),
        )

        allocate_buckets = lambda: self.storage_server.doRemoteCall(
            "allocate_buckets",
            (valid_passes,
             storage_index,
             renew_secret,
             cancel_secret,
             share_nums,
             allocated_size,
             LocalReferenceable(None),
            ),
            {},
        )
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
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

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
            self.assertThat(
                e.required_count,
                Equals(1),
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
            share by at least BYTES_PER_PASS.
        """
        # hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        tw_vectors = {
            k: v.for_call()
            for (k, v)
            in test_and_write_vectors_for_shares.items()
        }

        note("tw_vectors summarized: {}".format(summarize(tw_vectors)))

        # print("test suite")
        required_pass_count = get_required_new_passes_for_mutable_write(
            dict.fromkeys(tw_vectors.keys(), 0),
            tw_vectors,
        )

        valid_passes = make_passes(
            self.signing_key,
            slot_testv_and_readv_and_writev_message(storage_index),
            list(
                RandomToken.create()
                for i
                in range(required_pass_count)
            ),
        )

        # Create an initial share to toy with.
        test, read = self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=valid_passes,
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
                MatchesStructure(
                    valid_count=Equals(0),
                    required_count=Equals(1),
                ),
            )
        else:
            self.fail("expected MorePassesRequired, got {}".format(result))

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=test_and_write_vectors_for_shares(),
    )
    def test_extend_mutable_with_write_fails_without_passes(self, storage_index, secrets, test_and_write_vectors_for_shares):
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
                [(current_length, "x" * BYTES_PER_PASS)],
                None,
            ),
        )

    def _test_lease_operation_fails_without_passes(
            self,
            storage_index,
            secrets,
            sharenums,
            allocated_size,
            lease_operation,
            lease_operation_message,
    ):
        """
        Assert that a lease-taking operation fails if it is not supplied with
        enough passes to cover the cost of the lease.

        :param lease_operation: A two-argument callable.  It is called with a
            storage server and a list of passes.  It should perform the
            lease-taking operation.

        :param lease_operation_message: A one-argument callable.  It is called
            with a storage index.  It should return the ZKAPAuthorizer binding
            message for the lease-taking operation.
        """
        # hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        renew_secret, cancel_secret = secrets

        required_count = required_passes(BYTES_PER_PASS, [allocated_size] * len(sharenums))
        # Create some shares at a slot which will require lease renewal.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            allocated_size,
            LocalReferenceable(None),
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
        passes = make_passes(
            self.signing_key,
            lease_operation_message(storage_index),
            list(RandomToken.create() for i in range(required_count - 1)),
        )
        try:
            result = lease_operation(self.storage_server, passes)
        except MorePassesRequired as e:
            self.assertThat(
                e,
                MatchesStructure(
                    valid_count=Equals(len(passes)),
                    required_count=Equals(required_count),
                ),
            )
        else:
            self.fail("Expected MorePassesRequired, got {}".format(result))

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        sharenums=sharenum_sets(),
        allocated_size=sizes(),
    )
    def test_add_lease_fails_without_passes(self, storage_index, secrets, sharenums, allocated_size):
        """
        If ``remote_add_lease`` is invoked without supplying enough passes to
        cover the storage for all shares on the given storage index, the
        operation fails with ``MorePassesRequired``.
        """
        renew_secret, cancel_secret = secrets
        def add_lease(storage_server, passes):
            return storage_server.doRemoteCall(
                "add_lease", (
                    passes,
                    storage_index,
                    renew_secret,
                    cancel_secret,
                ),
                {},
            )
        return self._test_lease_operation_fails_without_passes(
            storage_index,
            secrets,
            sharenums,
            allocated_size,
            add_lease,
            add_lease_message,
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        sharenums=sharenum_sets(),
        allocated_size=sizes(),
    )
    def test_renew_lease_fails_without_passes(self, storage_index, secrets, sharenums, allocated_size):
        """
        If ``remote_renew_lease`` is invoked without supplying enough passes to
        cover the storage for all shares on the given storage index, the
        operation fails with ``MorePassesRequired``.
        """
        renew_secret, cancel_secret = secrets
        def renew_lease(storage_server, passes):
            return storage_server.doRemoteCall(
                "renew_lease", (
                    passes,
                    storage_index,
                    renew_secret,
                ),
                {},
            )
        return self._test_lease_operation_fails_without_passes(
            storage_index,
            secrets,
            sharenums,
            allocated_size,
            renew_lease,
            renew_lease_message,
        )

    @given(
        slot=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        sharenums=one_of(just(None), sharenum_sets()),
        test_and_write_vectors_for_shares=test_and_write_vectors_for_shares(),
    )
    def test_mutable_share_sizes(self, slot, secrets, sharenums, test_and_write_vectors_for_shares):
        """
        ``share_sizes`` returns the size of the requested mutable shares in the
        requested slot.
        """
        # hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        tw_vectors = {
            k: v.for_call()
            for (k, v)
            in test_and_write_vectors_for_shares.items()
        }

        # Create an initial share to toy with.
        required_pass_count = get_required_new_passes_for_mutable_write(
            dict.fromkeys(tw_vectors.keys(), 0),
            tw_vectors,
        )
        valid_passes = make_passes(
            self.signing_key,
            slot_testv_and_readv_and_writev_message(slot),
            list(
                RandomToken.create()
                for i
                in range(required_pass_count)
            ),
        )
        test, read = self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=valid_passes,
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
            for (sharenum, (testv, data_vector, new_length))
            in tw_vectors.items()
            if sharenums is None or sharenum in sharenums
        }

        actual_sizes = self.storage_server.doRemoteCall(
            "share_sizes", (
                slot,
                sharenums,
            ),
            {},
        )
        self.assertThat(
            actual_sizes,
            Equals(expected_sizes),
        )
