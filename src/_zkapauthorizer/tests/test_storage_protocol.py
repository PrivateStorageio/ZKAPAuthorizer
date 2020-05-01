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
Tests for communication between the client and server components.
"""

from __future__ import (
    absolute_import,
)

from fixtures import (
    MonkeyPatch,
)
from testtools import (
    TestCase,
)
from testtools.matchers import (
    Equals,
    HasLength,
    IsInstance,
    AfterPreprocessing,
    raises,
)
from testtools.twistedsupport import (
    succeeded,
    failed,
)
from testtools.twistedsupport._deferred import (
    # I'd rather use https://twistedmatrix.com/trac/ticket/8900 but efforts
    # there appear to have stalled.
    extract_result,
)

from hypothesis import (
    given,
    assume,
)
from hypothesis.strategies import (
    sets,
    lists,
    tuples,
    integers,
)

from twisted.python.runtime import (
    platform,
)
from twisted.python.filepath import (
    FilePath,
)

from foolscap.referenceable import (
    LocalReferenceable,
)

from challenge_bypass_ristretto import (
    RandomToken,
    random_signing_key,
)

from .common import (
    skipIf,
)

from .privacypass import (
    make_passes,
)
from .strategies import (
    storage_indexes,
    lease_renew_secrets,
    lease_cancel_secrets,
    write_enabler_secrets,
    sharenums,
    sharenum_sets,
    sizes,
    test_and_write_vectors_for_shares,
    clocks,
    # Not really a strategy...
    bytes_for_share,
)
from .matchers import (
    matches_version_dictionary,
)
from .fixtures import (
    AnonymousStorageServer,
)
from .storage_common import (
    cleanup_storage_server,
    write_toy_shares,
)
from .foolscap import (
    LocalRemote,
)
from ..api import (
    ZKAPAuthorizerStorageServer,
    ZKAPAuthorizerStorageClient,
)
from ..storage_common import (
    slot_testv_and_readv_and_writev_message,
    get_implied_data_length,
    required_passes,
)
from ..model import (
    Pass,
)
from ..foolscap import (
    ShareStat,
)


class RequiredPassesTests(TestCase):
    """
    Tests for ``required_passes``.
    """
    @given(integers(min_value=1), sets(integers(min_value=0)))
    def test_incorrect_types(self, bytes_per_pass, share_sizes):
        """
        ``required_passes`` raises ``TypeError`` if passed a ``set`` for
        ``share_sizes``.
        """
        self.assertThat(
            lambda: required_passes(bytes_per_pass, share_sizes),
            raises(TypeError),
        )

    @given(
        bytes_per_pass=integers(min_value=1),
        expected_per_share=lists(integers(min_value=1), min_size=1),
    )
    def test_minimum_result(self, bytes_per_pass, expected_per_share):
        """
        ``required_passes`` returns an integer giving the fewest passes required
        to pay for the storage represented by the given share sizes.
        """
        actual = required_passes(
            bytes_per_pass,
            list(
                passes * bytes_per_pass
                for passes
                in expected_per_share
            ),
        )
        self.assertThat(
            actual,
            Equals(sum(expected_per_share)),
        )


class ShareTests(TestCase):
    """
    Tests for interaction with shares.

    :ivar int spent_passes: The number of passes which have been spent so far
        in the course of a single test (in the case of Hypothesis, every
        iteration of the test so far, probably; so make relative comparisons
        instead of absolute ones).
    """
    pass_value = 128 * 1024

    def setUp(self):
        super(ShareTests, self).setUp()
        self.canary = LocalReferenceable(None)
        self.anonymous_storage_server = self.useFixture(AnonymousStorageServer()).storage_server
        self.signing_key = random_signing_key()
        self.spent_passes = 0

        def get_passes(message, count):
            self.spent_passes += count
            return list(
                Pass(*pass_.split(u" "))
                for pass_
                in make_passes(
                    self.signing_key,
                    message,
                    list(RandomToken.create() for n in range(count)),
                )
            )
        self.server = ZKAPAuthorizerStorageServer(
            self.anonymous_storage_server,
            self.pass_value,
            self.signing_key,
        )
        self.local_remote_server = LocalRemote(self.server)
        self.client = ZKAPAuthorizerStorageClient(
            self.pass_value,
            get_rref=lambda: self.local_remote_server,
            get_passes=get_passes,
        )

    def test_get_version(self):
        """
        Version information about the storage server can be retrieved using
        *get_version*.
        """
        self.assertThat(
            self.client.get_version(),
            succeeded(matches_version_dictionary()),
        )

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenums=sharenum_sets(),
        size=sizes(),
    )
    def test_create_immutable(self, storage_index, renew_secret, cancel_secret, sharenums, size):
        """
        Immutable share data created using *allocate_buckets* and methods of the
        resulting buckets can be read back using *get_buckets* and methods of
        those resulting buckets.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        alreadygot, allocated = extract_result(
            self.client.allocate_buckets(
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                size,
                canary=self.canary,
            ),
        )
        self.expectThat(
            alreadygot,
            Equals(set()),
            u"fresh server somehow already had shares",
        )
        self.expectThat(
            set(allocated.keys()),
            Equals(sharenums),
            u"fresh server refused to allocate all requested buckets",
        )

        for sharenum, bucket in allocated.items():
            bucket.remote_write(0, bytes_for_share(sharenum, size))
            bucket.remote_close()

        readers = extract_result(self.client.get_buckets(storage_index))

        self.expectThat(
            set(readers.keys()),
            Equals(sharenums),
            u"server did not return all buckets we wrote",
        )
        for (sharenum, bucket) in readers.items():
            self.expectThat(
                bucket.remote_read(0, size),
                Equals(bytes_for_share(sharenum, size)),
                u"server returned wrong bytes for share number {}".format(
                    sharenum,
                ),
            )

    @given(
        storage_index=storage_indexes(),
        renew_secrets=tuples(lease_renew_secrets(), lease_renew_secrets()),
        cancel_secret=lease_cancel_secrets(),
        sharenums=sharenum_sets(),
        size=sizes(),
    )
    def test_add_lease(self, storage_index, renew_secrets, cancel_secret, sharenums, size):
        """
        A lease can be added to an existing immutable share.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        # Use a different secret so that it's a new lease and not an
        # implicit renewal.
        add_lease_secret, renew_lease_secret = renew_secrets
        assume(add_lease_secret != renew_lease_secret)

        # Create a share we can toy with.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            add_lease_secret,
            cancel_secret,
            sharenums,
            size,
            canary=self.canary,
        )

        extract_result(
            self.client.add_lease(
                storage_index,
                renew_lease_secret,
                cancel_secret,
            ),
        )
        leases = list(self.anonymous_storage_server.get_leases(storage_index))
        self.assertThat(leases, HasLength(2))

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenums=sharenum_sets(),
        size=sizes(),
    )
    def test_renew_lease(self, storage_index, renew_secret, cancel_secret, sharenums, size):
        """
        A lease on an immutable share can be updated to expire at a later time.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        # Take control of time (in this hacky, fragile way) so we can verify
        # the expiration time gets bumped by the renewal.
        now = 1000000000.5
        self.useFixture(MonkeyPatch("time.time", lambda: now))

        # Create a share we can toy with.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            size,
            canary=self.canary,
        )

        now += 100000
        extract_result(
            self.client.renew_lease(
                storage_index,
                renew_secret,
            ),
        )

        [lease] = self.anonymous_storage_server.get_leases(storage_index)
        self.assertThat(
            lease.get_expiration_time(),
            Equals(int(now + self.server.LEASE_PERIOD.total_seconds())),
        )

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenum=sharenums(),
        size=sizes(),
        clock=clocks(),
        leases=lists(lease_renew_secrets(), unique=True),
    )
    def test_stat_shares_immutable(self, storage_index, renew_secret, cancel_secret, sharenum, size, clock, leases):
        """
        Size and lease information about immutable shares can be retrieved from a
        storage server.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        # anonymous_storage_server uses time.time(), unfortunately.  And
        # useFixture does not interact very well with Hypothesis.
        patch = MonkeyPatch("time.time", clock.seconds)
        try:
            patch.setUp()
            # Create a share we can toy with.
            write_toy_shares(
                self.anonymous_storage_server,
                storage_index,
                renew_secret,
                cancel_secret,
                {sharenum},
                size,
                canary=self.canary,
            )
            # Perhaps put some more leases on it.  Leases might impact our
            # ability to determine share data size.
            for renew_secret in leases:
                self.anonymous_storage_server.remote_add_lease(
                    storage_index,
                    renew_secret,
                    b"",
                )
        finally:
            patch.cleanUp()

        stats = extract_result(
            self.client.stat_shares([storage_index]),
        )
        # Hard-coded in Tahoe-LAFS
        LEASE_INTERVAL = 60 * 60 * 24 * 31
        expected = [{
            sharenum: ShareStat(
                size=size,
                lease_expiration=int(clock.seconds() + LEASE_INTERVAL),
            ),
        }]
        self.assertThat(
            stats,
            Equals(expected),
        )


    @skipIf(platform.isWindows(), "Storage server miscomputes slot size on Windows")
    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=test_and_write_vectors_for_shares(),
        clock=clocks(),
    )
    def test_stat_shares_mutable(self, storage_index, secrets, test_and_write_vectors_for_shares, clock):
        """
        Size and lease information about mutable shares can be retrieved from a
        storage server.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        # anonymous_storage_server uses time.time(), unfortunately.  And
        # useFixture does not interact very well with Hypothesis.
        patch = MonkeyPatch("time.time", clock.seconds)
        try:
            patch.setUp()
            # Create a share we can toy with.
            wrote, read = extract_result(
                self.client.slot_testv_and_readv_and_writev(
                    storage_index,
                    secrets=secrets,
                    tw_vectors={
                        k: v.for_call()
                        for (k, v)
                        in test_and_write_vectors_for_shares.items()
                    },
                    r_vector=[],
                ),
            )
        finally:
            patch.cleanUp()
        self.assertThat(
            wrote,
            Equals(True),
            u"Server rejected a write to a new mutable slot",
        )

        stats = extract_result(
            self.client.stat_shares([storage_index]),
        )
        # Hard-coded in Tahoe-LAFS
        LEASE_INTERVAL = 60 * 60 * 24 * 31
        expected = [{
            sharenum: ShareStat(
                size=get_implied_data_length(
                    vectors.write_vector,
                    vectors.new_length,
                ),
                lease_expiration=int(clock.seconds() + LEASE_INTERVAL),
            )
            for (sharenum, vectors)
            in test_and_write_vectors_for_shares.items()
        }]
        self.assertThat(
            stats,
            Equals(expected),
        )


    @skipIf(
        platform.isWindows(),
        "StorageServer fails to create necessary directory for corruption advisories in Windows.",
    )
    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenum=sharenums(),
        size=sizes(),
    )
    def test_advise_corrupt_share(self, storage_index, renew_secret, cancel_secret, sharenum, size):
        """
        An advisory of corruption in a share can be sent to the server.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        # Create a share we can toy with.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            {sharenum},
            size,
            canary=self.canary,
        )

        extract_result(
            self.client.advise_corrupt_share(
                b"immutable",
                storage_index,
                sharenum,
                b"the bits look bad",
            ),
        )
        self.assertThat(
            FilePath(self.anonymous_storage_server.corruption_advisory_dir).children(),
            HasLength(1),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=test_and_write_vectors_for_shares(),
    )
    def test_create_mutable(self, storage_index, secrets, test_and_write_vectors_for_shares):
        """
        Mutable share data written using *slot_testv_and_readv_and_writev* can be
        read back as-written and without spending any more passes.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        wrote, read = extract_result(
            self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors={
                    k: v.for_call()
                    for (k, v)
                    in test_and_write_vectors_for_shares.items()
                },
                r_vector=[],
            ),
        )
        self.assertThat(
            wrote,
            Equals(True),
            u"Server rejected a write to a new mutable slot",
        )
        self.assertThat(
            read,
            Equals({}),
            u"Server gave back read results when we asked for none.",
        )
        # Now we can read it back without spending any more passes.
        before_spent_passes = self.spent_passes
        assert_read_back_data(self, storage_index, secrets, test_and_write_vectors_for_shares)
        after_spent_passes = self.spent_passes
        self.assertThat(
            before_spent_passes,
            Equals(after_spent_passes),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=test_and_write_vectors_for_shares(),
    )
    def test_mutable_rewrite_preserves_lease(self, storage_index, secrets, test_and_write_vectors_for_shares):
        """
        When mutable share data is rewritten using
        *slot_testv_and_readv_and_writev* any leases on the corresponding slot
        remain the same.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        def leases():
            return list(
                lease.to_mutable_data()
                for lease
                in self.anonymous_storage_server.get_slot_leases(storage_index)
            )

        def write():
            return extract_result(
                self.client.slot_testv_and_readv_and_writev(
                    storage_index,
                    secrets=secrets,
                    tw_vectors={
                        k: v.for_call()
                        for (k, v)
                        in test_and_write_vectors_for_shares.items()
                    },
                    r_vector=[],
                ),
            )

        # Perform an initial write so there is something to rewrite.
        wrote, read = write()
        self.assertThat(
            wrote,
            Equals(True),
            u"Server rejected a write to a new mutable slot",
        )

        # Note the prior state.
        leases_before = leases()

        # Now perform the rewrite.
        wrote, read = write()
        self.assertThat(
            wrote,
            Equals(True),
            u"Server rejected rewrite of an existing mutable slot",
        )

        # Leases are exactly unchanged.
        self.assertThat(
            leases(),
            Equals(leases_before),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=test_and_write_vectors_for_shares(),
    )
    def test_client_cannot_control_lease_behavior(self, storage_index, secrets, test_and_write_vectors_for_shares):
        """
        If the client passes ``renew_leases`` to *slot_testv_and_readv_and_writev*
        it fails with ``TypeError``, no lease is updated, and no share data is
        written.
        """
        # First, tell the client to let us violate the protocol.  It is the
        # server's responsibility to defend against this attack.
        self.local_remote_server.check_args = False

        # The nice Python API doesn't let you do this so we drop down to
        # the layer below.  We also use positional arguments because they
        # transit the network differently from keyword arguments.  Yay.
        d = self.client._rref.callRemote(
            "slot_testv_and_readv_and_writev",
            # passes
            self.client._get_encoded_passes(
                slot_testv_and_readv_and_writev_message(storage_index),
                1,
            ),
            # storage_index
            storage_index,
            # secrets
            secrets,
            # tw_vectors
            {
                k: v.for_call()
                for (k, v)
                in test_and_write_vectors_for_shares.items()
            },
            # r_vector
            [],
            # add_leases
            True,
        )

        # The operation should fail.
        self.expectThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(TypeError),
                ),
            ),
        )

        # There should be no shares at the given storage index.
        d = self.client.slot_readv(
            storage_index,
            # Surprise.  shares=None means all shares.
            shares=None,
            r_vector=list(
                list(map(write_vector_to_read_vector, vector.write_vector))
                for vector
                in test_and_write_vectors_for_shares.values()
            ),
        )
        self.expectThat(
            d,
            succeeded(
                Equals({}),
            ),
        )

        # And there should be no leases on those non-shares.
        self.expectThat(
            list(self.anonymous_storage_server.get_slot_leases(storage_index)),
            Equals([]),
        )


def assert_read_back_data(self, storage_index, secrets, test_and_write_vectors_for_shares):
    """
    Assert that the data written by ``test_and_write_vectors_for_shares`` can
    be read back from ``storage_index``.

    :param ShareTests self: The test case which performed the write and can be
        used for assertions.

    :param bytes storage_index: The storage index where the data should be
        found.

    :raise: A test-failing assertion if the data cannot be read back.
    """
    # Create a buffer and pile up all the write operations in it.
    # This lets us make correct assertions about overlapping writes.
    for sharenum, vectors in test_and_write_vectors_for_shares.items():
        length = max(
            offset + len(data)
            for (offset, data)
            in vectors.write_vector
        )
        expected = b"\x00" * length
        for (offset, data) in vectors.write_vector:
            expected = expected[:offset] + data + expected[offset + len(data):]
        if vectors.new_length is not None and vectors.new_length < length:
            expected = expected[:vectors.new_length]

        expected_result = list(
            # Get the expected value out of our scratch buffer.
            expected[offset:offset + len(data)]
            for (offset, data)
            in vectors.write_vector
        )

        _, single_read = extract_result(
            self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors={},
                r_vector=list(map(write_vector_to_read_vector, vectors.write_vector)),
            ),
        )

        self.assertThat(
            single_read[sharenum],
            Equals(expected_result),
            u"Server didn't reliably read back data just written",
        )


def write_vector_to_read_vector(write_vector):
    """
    Create a read vector which will read back the data written by the given
    write vector.
    """
    return (write_vector[0], len(write_vector[1]))
