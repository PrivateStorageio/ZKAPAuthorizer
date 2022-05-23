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

from allmydata.storage.common import storage_index_to_dir
from allmydata.storage.shares import get_share_file
from challenge_bypass_ristretto import PublicKey, random_signing_key
from foolscap.referenceable import LocalReferenceable
from hypothesis import assume, given
from hypothesis.strategies import data as data_strategy
from hypothesis.strategies import integers, lists, sets, tuples
from testtools import TestCase
from testtools.content import text_content
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    Equals,
    HasLength,
    IsInstance,
    MatchesStructure,
    raises,
)
from testtools.twistedsupport import failed, succeeded

# I'd rather use https://twistedmatrix.com/trac/ticket/8900 but efforts
# there appear to have stalled.
from testtools.twistedsupport._deferred import extract_result
from twisted.internet.task import Clock
from twisted.python.filepath import FilePath
from twisted.python.runtime import platform

from ..api import (
    MorePassesRequired,
    ZKAPAuthorizerStorageClient,
    ZKAPAuthorizerStorageServer,
)
from ..foolscap import ShareStat
from ..server.spending import RecordingSpender
from ..storage_common import (
    allocate_buckets_message,
    get_implied_data_length,
    required_passes,
)
from .common import skipIf
from .fixtures import AnonymousStorageServer
from .foolscap import LocalRemote
from .matchers import matches_spent_passes, matches_version_dictionary
from .storage_common import (
    LEASE_INTERVAL,
    get_passes,
    pass_factory,
    privacypass_passes,
    reset_storage_server,
    whitebox_write_sparse_share,
    write_toy_shares,
)
from .strategies import bytes_for_share  # Not really a strategy...
from .strategies import (
    TestAndWriteVectors,
    lease_cancel_secrets,
    lease_renew_secrets,
    posix_timestamps,
    share_versions,
    sharenum_sets,
    sharenums,
    sizes,
    slot_data_vectors,
    slot_test_and_write_vectors_for_shares,
    storage_indexes,
    write_enabler_secrets,
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
            list(passes * bytes_per_pass for passes in expected_per_share),
        )
        self.assertThat(
            actual,
            Equals(sum(expected_per_share)),
        )


def is_successful_write():
    """
    Match the successful result of a ``slot_testv_and_readv_and_writev`` call.
    """
    return succeeded(
        AfterPreprocessing(
            lambda result: result[0],
            Equals(True),
        ),
    )


class ShareTests(TestCase):
    """
    Tests for interaction with shares.

    :ivar pass_factory: An object which is responsible for creating passes
        which are used by these tests.
    """

    pass_value = 128 * 1024

    def setUp(self):
        super(ShareTests, self).setUp()
        self.canary = LocalReferenceable(None)
        self.signing_key = random_signing_key()
        self.public_key_hash = PublicKey.from_signing_key(
            self.signing_key
        ).encode_base64()
        self.pass_factory = pass_factory(
            get_passes=privacypass_passes(self.signing_key)
        )

        self.clock = Clock()
        self.anonymous_storage_server = self.useFixture(
            AnonymousStorageServer(self.clock),
        ).storage_server

        self.spending_recorder, spender = RecordingSpender.make()
        self.server = ZKAPAuthorizerStorageServer(
            self.anonymous_storage_server,
            self.pass_value,
            self.signing_key,
            spender,
            clock=self.clock,
        )
        self.local_remote_server = LocalRemote(self.server)
        self.client = ZKAPAuthorizerStorageClient(
            self.pass_value,
            get_rref=lambda: self.local_remote_server,
            get_passes=self.pass_factory.get,
            clock=self.clock,
        )

    def setup_example(self):
        """
        Initialize any necessary state prior to each Hypothesis iteration of a
        test method.
        """
        # Reset the mutable, shared clock to the epoch to simplify related
        # code in the tests and ensure consistent starting state for each
        # iteration.
        self.clock.advance(-self.clock.seconds())

        # Reset the state of any passes in our pass factory.
        self.pass_factory._clear()

        # Reset any record of spent tokens.
        self.spending_recorder.reset()

        # And clean out any shares that might confuse things.
        reset_storage_server(self.anonymous_storage_server)

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
        data=data_strategy(),
    )
    def test_rejected_passes_reported(
        self, storage_index, renew_secret, cancel_secret, sharenums, size, data
    ):
        """
        Any passes rejected by the storage server are reported with a
        ``MorePassesRequired`` exception sent to the client.
        """
        num_passes = required_passes(self.pass_value, [size] * len(sharenums))

        # Pick some passes to mess with.
        bad_pass_indexes = data.draw(
            lists(
                integers(
                    min_value=0,
                    max_value=num_passes - 1,
                ),
                min_size=1,
                max_size=num_passes,
                unique=True,
            ),
        )

        # Make some passes with a key untrusted by the server.
        bad_passes = get_passes(
            allocate_buckets_message(storage_index),
            len(bad_pass_indexes),
            random_signing_key(),
        )

        # Make some passes with a key trusted by the server.
        good_passes = get_passes(
            allocate_buckets_message(storage_index),
            num_passes - len(bad_passes),
            self.signing_key,
        )

        all_passes = []
        for i in range(num_passes):
            if i in bad_pass_indexes:
                all_passes.append(bad_passes.pop())
            else:
                all_passes.append(good_passes.pop())

        # Sanity checks
        self.assertThat(bad_passes, Equals([]))
        self.assertThat(good_passes, Equals([]))
        self.assertThat(all_passes, HasLength(num_passes))

        self.assertThat(
            # Bypass the client handling of MorePassesRequired so we can see
            # it.
            self.local_remote_server.callRemote(
                "allocate_buckets",
                list(pass_.pass_bytes for pass_ in all_passes),
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                size,
                canary=self.canary,
            ),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    Equals(
                        MorePassesRequired(
                            valid_count=num_passes - len(bad_pass_indexes),
                            required_count=num_passes,
                            signature_check_failed=bad_pass_indexes,
                        ),
                    ),
                ),
            ),
        )

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenums=sharenum_sets(),
        size=sizes(),
    )
    def test_create_immutable(
        self, storage_index, renew_secret, cancel_secret, sharenums, size
    ):
        """
        Immutable share data created using *allocate_buckets* and methods of the
        resulting buckets can be read back using *get_buckets* and methods of
        those resulting buckets.
        """
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
            "fresh server somehow already had shares",
        )
        self.expectThat(
            set(allocated.keys()),
            Equals(sharenums),
            "fresh server refused to allocate all requested buckets",
        )
        self.expectThat(
            self.spending_recorder,
            matches_spent_passes(self.public_key_hash, self.pass_factory.spent_passes),
        )

        for sharenum, bucket in allocated.items():
            bucket.remote_write(0, bytes_for_share(sharenum, size))
            bucket.remote_close()

        readers = extract_result(self.client.get_buckets(storage_index))

        self.expectThat(
            set(readers.keys()),
            Equals(sharenums),
            "server did not return all buckets we wrote",
        )
        for (sharenum, bucket) in readers.items():
            self.expectThat(
                bucket.remote_read(0, size),
                Equals(bytes_for_share(sharenum, size)),
                "server returned wrong bytes for share number {}".format(
                    sharenum,
                ),
            )

        # Enough passes for all the sharenums should have been spent.
        anticipated_passes = required_passes(
            self.pass_value,
            [size] * len(sharenums),
        )

        self.assertThat(
            self.pass_factory,
            MatchesStructure(
                issued=HasLength(anticipated_passes),
                spent=HasLength(anticipated_passes),
                returned=HasLength(0),
                in_use=HasLength(0),
                invalid=HasLength(0),
            ),
        )

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        existing_sharenums=sharenum_sets(),
        additional_sharenums=sharenum_sets(),
        when=posix_timestamps(),
        interval=integers(min_value=1, max_value=60 * 60 * 24 * 31),
        size=sizes(),
    )
    def test_shares_already_exist(
        self,
        storage_index,
        renew_secret,
        cancel_secret,
        existing_sharenums,
        additional_sharenums,
        when,
        interval,
        size,
    ):
        """
        When the remote *allocate_buckets* implementation reports that shares
        already exist, passes are not spent for those shares.
        """
        # A helper that only varies on sharenums.
        def allocate_buckets(sharenums):
            alreadygot, writers = extract_result(
                self.client.allocate_buckets(
                    storage_index,
                    renew_secret,
                    cancel_secret,
                    sharenums,
                    size,
                    canary=self.canary,
                ),
            )
            for sharenum, writer in writers.items():
                writer.remote_write(0, bytes_for_share(sharenum, size))
                writer.remote_close()

        # Set some arbitrary time so we can inspect lease renewal behavior.
        self.clock.advance(when)

        # Create some shares to alter the behavior of the next
        # allocate_buckets.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            existing_sharenums,
            size,
        )

        # Let some time pass so leases added after this point will look
        # different from leases added before this point.
        self.clock.advance(interval)

        # Do a partial repeat of the operation.  Shuffle around
        # the shares in some random-ish way.  If there is partial overlap
        # there should be partial spending.
        all_sharenums = existing_sharenums | additional_sharenums
        allocate_buckets(all_sharenums)

        # This is what the client should try to spend.  This should also match
        # the total number of passes issued during the test.
        anticipated_passes = required_passes(
            self.pass_value,
            [size] * len(all_sharenums),
        )

        # The number of passes that will *actually* need to be spent depends
        # on the size and number of shares that really need to be allocated.
        expected_spent_passes = required_passes(
            self.pass_value,
            [size] * len(all_sharenums - existing_sharenums),
        )

        # The number of passes returned is just the difference between those
        # two.
        expected_returned_passes = anticipated_passes - expected_spent_passes

        # Only enough passes for the not-already-uploaded sharenums should
        # have been spent.
        self.assertThat(
            self.pass_factory,
            MatchesStructure(
                issued=HasLength(anticipated_passes),
                spent=HasLength(expected_spent_passes),
                returned=HasLength(expected_returned_passes),
                in_use=HasLength(0),
                invalid=HasLength(0),
            ),
        )

        # The spent passes have been reported to the spending service.
        self.assertThat(
            self.spending_recorder,
            matches_spent_passes(self.public_key_hash, self.pass_factory.spent_passes),
        )

        expected_leases = {}
        # Chop off the non-integer part of the expected values because share
        # files only keep integer precision.
        expected_leases.update(
            {sharenum: [int(when)] for sharenum in existing_sharenums}
        )
        expected_leases.update(
            {
                sharenum: [int(when + interval)]
                for sharenum in all_sharenums - existing_sharenums
            }
        )

        self.assertThat(
            dict(get_lease_grant_times(self.anonymous_storage_server, storage_index)),
            Equals(expected_leases),
        )

    @given(
        storage_index=storage_indexes(),
        renew_secrets=tuples(lease_renew_secrets(), lease_renew_secrets()),
        cancel_secret=lease_cancel_secrets(),
        sharenums=sharenum_sets(),
        size=sizes(),
    )
    def test_add_lease(
        self, storage_index, renew_secrets, cancel_secret, sharenums, size
    ):
        """
        A lease can be added to an existing immutable share.
        """
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
        )

        self.assertThat(
            self.client.add_lease(
                storage_index,
                renew_lease_secret,
                cancel_secret,
            ),
            succeeded(Always()),
        )

        # The spent passes have been reported to the spending service.
        self.assertThat(
            self.spending_recorder,
            matches_spent_passes(self.public_key_hash, self.pass_factory.spent_passes),
        )

        leases = list(self.anonymous_storage_server.get_leases(storage_index))
        self.assertThat(leases, HasLength(2))

    def _stat_shares_immutable_test(
        self, storage_index, sharenum, size, when, leases, write_shares
    ):
        # Lease cancellation is unimplemented in Tahoe so this doesn't matter.
        cancel_secret = b""

        self.clock.advance(when)

        # Create a share we can toy with.
        write_shares(
            self.anonymous_storage_server,
            storage_index,
            {sharenum},
            size,
            canary=self.canary,
        )
        # Perhaps put some more leases on it.  Leases might impact our
        # ability to determine share data size.
        for renew_secret in leases:
            self.anonymous_storage_server.add_lease(
                storage_index,
                renew_secret,
                cancel_secret,
            )

        expected = [
            {
                sharenum: ShareStat(
                    size=size,
                    lease_expiration=int(self.clock.seconds() + LEASE_INTERVAL),
                ),
            }
        ]
        self.assertThat(
            self.client.stat_shares([storage_index]),
            succeeded(Equals(expected)),
        )

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenum=sharenums(),
        size=sizes(),
        when=posix_timestamps(),
        leases=lists(lease_renew_secrets(), unique=True),
    )
    def test_stat_shares_immutable(
        self, storage_index, renew_secret, cancel_secret, sharenum, size, when, leases
    ):
        """
        Size and lease information about immutable shares can be retrieved from a
        storage server.
        """
        return self._stat_shares_immutable_test(
            storage_index,
            sharenum,
            size,
            when,
            leases,
            lambda storage_server, storage_index, sharenums, size, canary: write_toy_shares(
                storage_server,
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                size,
            ),
        )

    @given(
        storage_index=storage_indexes(),
        sharenum=sharenums(),
        size=sizes(),
        when=posix_timestamps(),
        leases=lists(lease_renew_secrets(), unique=True, min_size=1),
        version=share_versions(),
    )
    def test_stat_shares_immutable_wrong_version(
        self, storage_index, sharenum, size, when, leases, version
    ):
        """
        If a share file with an unexpected version is found, ``stat_shares``
        declines to offer a result (by raising ``ValueError``).
        """
        assume(version not in (1, 2))

        sharedir = FilePath(self.anonymous_storage_server.sharedir).preauthChild(
            # storage_index_to_dir likes to return multiple segments
            # joined by pathsep
            storage_index_to_dir(storage_index),
        )
        sharepath = sharedir.child("{}".format(sharenum))
        sharepath.parent().makedirs()
        whitebox_write_sparse_share(
            sharepath,
            version=version,
            size=size,
            leases=leases,
            now=when,
        )

        self.assertThat(
            self.client.stat_shares([storage_index]),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(ValueError),
                ),
            ),
        )

    @given(
        storage_index=storage_indexes(),
        sharenum=sharenums(),
        size=sizes(),
        when=posix_timestamps(),
        version=share_versions(),
        # Encode our knowledge of the share header format and size right here...
        position=integers(min_value=0, max_value=11),
    )
    def test_stat_shares_truncated_file(
        self, storage_index, sharenum, size, when, version, position
    ):
        """
        If a share file is truncated in the middle of the header,
        ``stat_shares`` declines to offer a result (by raising
        ``ValueError``).
        """
        sharedir = FilePath(self.anonymous_storage_server.sharedir).preauthChild(
            # storage_index_to_dir likes to return multiple segments
            # joined by pathsep
            storage_index_to_dir(storage_index),
        )
        sharepath = sharedir.child("{}".format(sharenum))
        sharepath.parent().makedirs()
        whitebox_write_sparse_share(
            sharepath,
            version=version,
            size=size,
            # We know leases are at the end, where they'll get chopped off, so
            # we don't bother to write any.
            leases=[],
            now=when,
        )
        with sharepath.open("wb") as fobj:
            fobj.truncate(position)

        self.assertThat(
            self.client.stat_shares([storage_index]),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(ValueError),
                ),
            ),
        )

    @skipIf(
        platform.isWindows(),
        "Creating large files on Windows (no sparse files) is too slow",
    )
    @given(
        storage_index=storage_indexes(),
        sharenum=sharenums(),
        size=sizes(min_value=2**18, max_value=2**40),
        when=posix_timestamps(),
        leases=lists(lease_renew_secrets(), unique=True, min_size=1),
    )
    def test_stat_shares_immutable_large(
        self, storage_index, sharenum, size, when, leases
    ):
        """
        Size and lease information about very large immutable shares can be
        retrieved from a storage server.

        This is more of a whitebox test.  It assumes knowledge of Tahoe-LAFS
        share placement and layout.  This is necessary to avoid having to
        write real multi-gigabyte files to exercise the behavior.
        """

        def write_shares(storage_server, storage_index, sharenums, size, canary):
            sharedir = FilePath(storage_server.sharedir).preauthChild(
                # storage_index_to_dir likes to return multiple segments
                # joined by pathsep
                storage_index_to_dir(storage_index),
            )
            for sharenum in sharenums:
                sharepath = sharedir.child("{}".format(sharenum))
                sharepath.parent().makedirs()
                whitebox_write_sparse_share(
                    sharepath,
                    version=1,
                    size=size,
                    leases=leases,
                    now=when,
                )

        return self._stat_shares_immutable_test(
            storage_index,
            sharenum,
            size,
            when,
            leases,
            write_shares,
        )

    @skipIf(platform.isWindows(), "Storage server miscomputes slot size on Windows")
    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
        when=posix_timestamps(),
    )
    def test_stat_shares_mutable(
        self, storage_index, secrets, test_and_write_vectors_for_shares, when
    ):
        """
        Size and lease information about mutable shares can be retrieved from a
        storage server.
        """
        self.clock.advance(when)

        # Create a share we can toy with.
        wrote, read = extract_result(
            self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors={
                    k: v.for_call()
                    for (k, v) in test_and_write_vectors_for_shares.items()
                },
                r_vector=[],
            ),
        )
        self.assertThat(
            wrote,
            Equals(True),
            "Server rejected a write to a new mutable slot",
        )

        # The spent passes have been reported to the spending service.
        self.assertThat(
            self.spending_recorder,
            matches_spent_passes(self.public_key_hash, self.pass_factory.spent_passes),
        )

        expected = [
            {
                sharenum: ShareStat(
                    size=get_implied_data_length(
                        vectors.write_vector,
                        vectors.new_length,
                    ),
                    lease_expiration=int(self.clock.seconds() + LEASE_INTERVAL),
                )
                for (sharenum, vectors) in test_and_write_vectors_for_shares.items()
            }
        ]
        self.assertThat(
            self.client.stat_shares([storage_index]),
            succeeded(Equals(expected)),
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
    def test_advise_corrupt_share(
        self, storage_index, renew_secret, cancel_secret, sharenum, size
    ):
        """
        An advisory of corruption in a share can be sent to the server.
        """
        # Create a share we can toy with.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            {sharenum},
            size,
        )

        self.assertThat(
            self.client.advise_corrupt_share(
                b"immutable",
                storage_index,
                sharenum,
                b"the bits look bad",
            ),
            succeeded(Always()),
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
        share_vectors=lists(slot_test_and_write_vectors_for_shares(), min_size=1),
        now=posix_timestamps(),
    )
    def test_create_mutable(self, storage_index, secrets, share_vectors, now):
        """
        Mutable share data written using *slot_testv_and_readv_and_writev* can be
        read back as-written and without spending any more passes.
        """
        self.clock.advance(now)

        def write(vector):
            return self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors={k: v.for_call() for (k, v) in vector.items()},
                r_vector=[],
            )

        grant_times = {}
        for n, vector in enumerate(share_vectors):
            # Execute one of the write operations.  It might write to multiple
            # shares.
            self.assertThat(
                write(vector),
                is_successful_write(),
            )

            # Track our progress through the list of write vectors for
            # testtools failure reporting.  Each call overwrites the previous
            # detail so we can see how far we got, if we happen to fail
            # somewhere in this loop.
            self.addDetail("writev-progress", text_content("{}".format(n)))

            # Track the simulated time when each lease receives its lease.
            # This scenario is constructed so that only the first write to any
            # given share will result in a lease so we do not allow the grant
            # time for a given share number to be updated here.  Only
            # sharenums being written for the first time will capture the time
            # here.
            grant_times.update(
                {
                    # The time is in a list to make it easier to compare the
                    # result with the return value of `get_lease_grant_times`
                    # later.  The time is truncated to the integer portion
                    # because that is how much precision leases keep.
                    sharenum: [int(self.clock.seconds())]
                    for sharenum in vector
                    if sharenum not in grant_times
                }
            )

            # Advance time so the grant times will be distinct.
            self.clock.advance(1)

        # Now we can read back the last data written without spending any more
        # passes.
        before_passes = len(self.pass_factory.issued)
        assert_read_back_data(
            self,
            storage_index,
            secrets,
            share_vectors[-1],
        )
        after_passes = len(self.pass_factory.issued)
        self.assertThat(
            before_passes,
            Equals(after_passes),
        )

        # The spent passes have been reported to the spending service.
        self.assertThat(
            self.spending_recorder,
            matches_spent_passes(self.public_key_hash, self.pass_factory.spent_passes),
        )

        # And the lease we paid for on every share is present.
        self.assertThat(
            dict(
                get_lease_grant_times(
                    self.anonymous_storage_server,
                    storage_index,
                )
            ),
            Equals(grant_times),
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
    def test_mutable_rewrite_preserves_lease(
        self, storage_index, secrets, test_and_write_vectors_for_shares
    ):
        """
        When mutable share data is rewritten using
        *slot_testv_and_readv_and_writev* any leases on the corresponding slot
        remain the same.
        """

        def leases():
            return list(
                lease.to_mutable_data()
                for lease in self.anonymous_storage_server.get_slot_leases(
                    storage_index
                )
            )

        def write():
            return self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors={
                    k: v.for_call()
                    for (k, v) in test_and_write_vectors_for_shares.items()
                },
                r_vector=[],
            )

        # Perform an initial write so there is something to rewrite.
        self.assertThat(
            write(),
            is_successful_write(),
            "Server rejected a write to a new mutable slot",
        )

        # Note the prior state.
        leases_before = leases()

        # Now perform the rewrite.
        self.assertThat(
            write(),
            is_successful_write(),
            "Server rejected rewrite of an existing mutable slot",
        )

        # Leases are exactly unchanged.
        self.assertThat(
            leases(),
            Equals(leases_before),
        )

    @given(
        storage_index=storage_indexes(),
        sharenum=sharenums(),
        size=sizes(),
        when=posix_timestamps(),
        write_enabler=write_enabler_secrets(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
    )
    def test_mutable_rewrite_renews_expired_lease(
        self,
        storage_index,
        when,
        sharenum,
        size,
        write_enabler,
        renew_secret,
        cancel_secret,
        test_and_write_vectors_for_shares,
    ):
        """
        When mutable share data with an expired lease is rewritten using
        *slot_testv_and_readv_and_writev* a new lease is paid for and granted.
        """
        self.clock.advance(when)

        secrets = (write_enabler, renew_secret, cancel_secret)

        def write():
            return self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors={
                    k: v.for_call()
                    for (k, v) in test_and_write_vectors_for_shares.items()
                },
                r_vector=[],
            )

        # Create a share we can toy with.
        self.assertThat(write(), is_successful_write())

        # Advance time by more than a lease period so the lease is no
        # longer valid.
        self.clock.advance(self.server.LEASE_PERIOD.total_seconds() + 1)

        self.assertThat(write(), is_successful_write())

        # The spent passes have been reported to the spending service.
        self.assertThat(
            self.spending_recorder,
            matches_spent_passes(self.public_key_hash, self.pass_factory.spent_passes),
        )

        # Not only should the write above succeed but the lease should now be
        # marked as expiring one additional lease period into the future.
        self.assertThat(
            self.server.remote_stat_shares([storage_index]),
            Equals(
                [
                    {
                        num: ShareStat(
                            size=get_implied_data_length(
                                test_and_write_vectors_for_shares[num].write_vector,
                                test_and_write_vectors_for_shares[num].new_length,
                            ),
                            lease_expiration=int(
                                self.clock.seconds()
                                + self.server.LEASE_PERIOD.total_seconds()
                            ),
                        )
                        for num in test_and_write_vectors_for_shares
                    }
                ]
            ),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        sharenum=sharenums(),
        data_vector=slot_data_vectors(),
        replacement_data_vector=slot_data_vectors(),
    )
    def test_test_vectors_match(
        self, storage_index, secrets, sharenum, data_vector, replacement_data_vector
    ):
        """
        If test vectors are given then the write is allowed if they match the
        existing data.
        """
        empty_test_vector = []

        def write(tw_vectors):
            return self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors=tw_vectors,
                r_vector=[],
            )

        def read(sharenum, readv):
            d = self.client.slot_readv(storage_index, [sharenum], readv)
            d.addCallback(lambda data: data[sharenum])
            return d

        def equal_test_vector(data_vector):
            return list((offset, len(data), data) for (offset, data) in data_vector)

        # Create the share
        d = write(
            {
                sharenum: (empty_test_vector, data_vector, None),
            }
        )
        self.assertThat(d, is_successful_write())

        # Write some new data with a correct test vector.  We can only be sure
        # we know data from the last element of the test vector since earlier
        # elements may have been overwritten so only use that last element in
        # our test vector.
        d = write(
            {
                sharenum: (
                    equal_test_vector(data_vector)[-1:],
                    replacement_data_vector,
                    None,
                ),
            }
        )
        self.assertThat(d, is_successful_write())

        # Check that the new data is present
        assert_read_back_data(
            self,
            storage_index,
            secrets,
            {sharenum: TestAndWriteVectors(None, replacement_data_vector, None)},
        )


def assert_read_back_data(
    self, storage_index, secrets, test_and_write_vectors_for_shares
):
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
        length = max(offset + len(data) for (offset, data) in vectors.write_vector)
        expected = b"\x00" * length
        for (offset, data) in vectors.write_vector:
            expected = expected[:offset] + data + expected[offset + len(data) :]
        if vectors.new_length is not None and vectors.new_length < length:
            expected = expected[: vectors.new_length]

        expected_result = list(
            # Get the expected value out of our scratch buffer.
            expected[offset : offset + len(data)]
            for (offset, data) in vectors.write_vector
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
            "Server didn't reliably read back data just written",
        )


def write_vector_to_read_vector(write_vector):
    """
    Create a read vector which will read back the data written by the given
    write vector.
    """
    return (write_vector[0], len(write_vector[1]))


def get_lease_grant_times(storage_server, storage_index):
    """
    Get the grant times for all of the leases for all of the shares at the
    given storage index.
    """
    try:
        # Tahoe-LAFS 1.17.1 and earlier
        get_shares = storage_server._get_bucket_shares
    except AttributeError:
        # Newer than Tahoe-LAFS 1.17.1
        get_shares = storage_server.get_shares

    shares = get_shares(storage_index)
    for sharenum, sharepath in shares:
        sharefile = get_share_file(sharepath)
        leases = sharefile.get_leases()
        grant_times = list(lease.get_grant_renew_time_time() for lease in leases)
        yield sharenum, grant_times
