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
    Always,
    Equals,
    HasLength,
    IsInstance,
    AfterPreprocessing,
    MatchesStructure,
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
    data as data_strategy,
)

from twisted.python.runtime import (
    platform,
)
from twisted.python.filepath import (
    FilePath,
)
from twisted.internet.task import (
    Clock,
)

from foolscap.referenceable import (
    LocalReferenceable,
)

from challenge_bypass_ristretto import (
    random_signing_key,
)

from allmydata.storage.common import (
    storage_index_to_dir,
)

from .common import (
    skipIf,
)

from .strategies import (
    storage_indexes,
    lease_renew_secrets,
    lease_cancel_secrets,
    write_enabler_secrets,
    share_versions,
    sharenums,
    sharenum_sets,
    sizes,
    slot_test_and_write_vectors_for_shares,
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
    LEASE_INTERVAL,
    cleanup_storage_server,
    write_toy_shares,
    whitebox_write_sparse_share,
    get_passes,
    privacypass_passes,
    pass_factory,
)
from .foolscap import (
    LocalRemote,
)
from ..api import (
    MorePassesRequired,
    ZKAPAuthorizerStorageServer,
    ZKAPAuthorizerStorageClient,
)
from ..storage_common import (
    slot_testv_and_readv_and_writev_message,
    allocate_buckets_message,
    get_implied_data_length,
    required_passes,
)
from .._storage_client import (
    _encode_passes,
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


def synchronize_clocks(from_clock, to_clock):
    """
    Make the time on ``to_clock`` match the time on ``from_clock``.

    :param Clock from_clock: The clock from which to take the time.
    :param Clock to_clock: The clock to which to write a time.
    """
    to_clock.advance(from_clock.seconds() - to_clock.seconds())


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
        self.pass_factory = pass_factory(get_passes=privacypass_passes(self.signing_key))

        # Unfortunately we need to supply a Clock to AnonymousStorageServer
        # now.  But Hypothesis won't give us the Clock it wants us to use
        # until later. :/ We work around this by synchronizing this clock with
        # the Hypothesis-supplied clock in the tests whenever time changed.
        # It would be nice to find a different factoring that avoided this
        # duplication.
        self.clock = Clock()
        self.anonymous_storage_server = self.useFixture(
            AnonymousStorageServer(self.clock),
        ).storage_server

        self.server = ZKAPAuthorizerStorageServer(
            self.anonymous_storage_server,
            self.pass_value,
            self.signing_key,
            clock=self.clock,
        )
        self.local_remote_server = LocalRemote(self.server)
        self.client = ZKAPAuthorizerStorageClient(
            self.pass_value,
            get_rref=lambda: self.local_remote_server,
            get_passes=self.pass_factory.get,
            clock=self.clock,
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
        data=data_strategy(),
    )
    def test_rejected_passes_reported(self, storage_index, renew_secret, cancel_secret, sharenums, size, data):
        """
        Any passes rejected by the storage server are reported with a
        ``MorePassesRequired`` exception sent to the client.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

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
                list(
                    pass_.pass_text.encode("ascii")
                    for pass_
                    in all_passes
                ),
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
    def test_create_immutable(self, storage_index, renew_secret, cancel_secret, sharenums, size):
        """
        Immutable share data created using *allocate_buckets* and methods of the
        resulting buckets can be read back using *get_buckets* and methods of
        those resulting buckets.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        # Oops our pass factory, too. :(
        self.pass_factory._clear()

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
        size=sizes(),
    )
    def test_shares_already_exist(
            self,
            storage_index,
            renew_secret,
            cancel_secret,
            existing_sharenums,
            additional_sharenums,
            size,
    ):
        """
        When the remote *allocate_buckets* implementation reports that shares
        already exist, passes are not spent for those shares.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        # Oops our pass factory, too. :(
        self.pass_factory._clear()

        # A helper that only varies on sharenums.
        def allocate_buckets(sharenums):
            return self.client.allocate_buckets(
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                size,
                canary=self.canary,
            )

        # Create some shares to alter the behavior of the next
        # allocate_buckets.
        write_toy_shares(
            self.anonymous_storage_server,
            storage_index,
            renew_secret,
            cancel_secret,
            existing_sharenums,
            size,
            canary=self.canary,
        )

        # Do a partial repeat of the operation.  Shuffle around
        # the shares in some random-ish way.  If there is partial overlap
        # there should be partial spending.
        all_sharenums = existing_sharenums | additional_sharenums
        self.assertThat(
            allocate_buckets(all_sharenums),
            succeeded(Always()),
        )

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

        self.assertThat(
            self.client.add_lease(
                storage_index,
                renew_lease_secret,
                cancel_secret,
            ),
            succeeded(Always()),
        )
        leases = list(self.anonymous_storage_server.get_leases(storage_index))
        self.assertThat(leases, HasLength(2))

    def _stat_shares_immutable_test(self, storage_index, sharenum, size, clock, leases, write_shares):
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        # Lease cancellation is unimplemented in Tahoe so this doesn't matter.
        cancel_secret = b""

        # self.clock is shared across all of the Hypothesis cases that get
        # run.  That means we probably already advanced it to something.
        # Hypothesis might want to try a case where time is further in the
        # past than an earlier case - so we possibly rewind the clock here.
        synchronize_clocks(from_clock=clock, to_clock=self.clock)

        # anonymous_storage_server uses time.time() before Tahoe-LAFS 1.16,
        # unfortunately.  For Tahoe-LAFS 1.16, AnonymousStorageServer will
        # glue self.clock in for us.  For older versions we still need this
        # monkey-patching.
        #
        # And useFixture does not interact very well with Hypothesis.
        patch = MonkeyPatch("time.time", clock.seconds)
        try:
            patch.setUp()
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
                self.anonymous_storage_server.remote_add_lease(
                    storage_index,
                    renew_secret,
                    cancel_secret,
                )
        finally:
            patch.cleanUp()

        expected = [{
            sharenum: ShareStat(
                size=size,
                lease_expiration=int(clock.seconds() + LEASE_INTERVAL),
            ),
        }]
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
        clock=clocks(),
        leases=lists(lease_renew_secrets(), unique=True),
    )
    def test_stat_shares_immutable(self, storage_index, renew_secret, cancel_secret, sharenum, size, clock, leases):
        """
        Size and lease information about immutable shares can be retrieved from a
        storage server.
        """
        return self._stat_shares_immutable_test(
            storage_index,
            sharenum,
            size,
            clock,
            leases,
            lambda storage_server, storage_index, sharenums, size, canary: write_toy_shares(
                storage_server,
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                size,
                canary,
            ),
        )

    @given(
        storage_index=storage_indexes(),
        sharenum=sharenums(),
        size=sizes(),
        clock=clocks(),
        leases=lists(lease_renew_secrets(), unique=True, min_size=1),
        version=share_versions(),
    )
    def test_stat_shares_immutable_wrong_version(self, storage_index, sharenum, size, clock, leases, version):
        """
        If a share file with an unexpected version is found, ``stat_shares``
        declines to offer a result (by raising ``ValueError``).
        """
        assume(version != 1)

        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        sharedir = FilePath(self.anonymous_storage_server.sharedir).preauthChild(
            # storage_index_to_dir likes to return multiple segments
            # joined by pathsep
            storage_index_to_dir(storage_index),
        )
        sharepath = sharedir.child(u"{}".format(sharenum))
        sharepath.parent().makedirs()
        whitebox_write_sparse_share(
            sharepath,
            version=version,
            size=size,
            leases=leases,
            now=clock.seconds(),
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
        clock=clocks(),
        version=share_versions(),
        # Encode our knowledge of the share header format and size right here...
        position=integers(min_value=0, max_value=11),
    )
    def test_stat_shares_truncated_file(self, storage_index, sharenum, size, clock, version, position):
        """
        If a share file is truncated in the middle of the header,
        ``stat_shares`` declines to offer a result (by raising
        ``ValueError``).
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        sharedir = FilePath(self.anonymous_storage_server.sharedir).preauthChild(
            # storage_index_to_dir likes to return multiple segments
            # joined by pathsep
            storage_index_to_dir(storage_index),
        )
        sharepath = sharedir.child(u"{}".format(sharenum))
        sharepath.parent().makedirs()
        whitebox_write_sparse_share(
            sharepath,
            version=version,
            size=size,
            # We know leases are at the end, where they'll get chopped off, so
            # we don't bother to write any.
            leases=[],
            now=clock.seconds(),
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


    @skipIf(platform.isWindows(), "Creating large files on Windows (no sparse files) is too slow")
    @given(
        storage_index=storage_indexes(),
        sharenum=sharenums(),
        size=sizes(min_value=2 ** 18, max_value=2 ** 40),
        clock=clocks(),
        leases=lists(lease_renew_secrets(), unique=True, min_size=1),
    )
    def test_stat_shares_immutable_large(self, storage_index, sharenum, size, clock, leases):
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
                sharepath = sharedir.child(u"{}".format(sharenum))
                sharepath.parent().makedirs()
                whitebox_write_sparse_share(
                    sharepath,
                    version=1,
                    size=size,
                    leases=leases,
                    now=clock.seconds(),
                )

        return self._stat_shares_immutable_test(
            storage_index,
            sharenum,
            size,
            clock,
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

        # See the comment in `_stat_shares_immutable_test` for an explanation
        # of clock handling and time.time monkey-patching.
        synchronize_clocks(from_clock=clock, to_clock=self.clock)
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
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
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
        before_passes = len(self.pass_factory.issued)
        assert_read_back_data(self, storage_index, secrets, test_and_write_vectors_for_shares)
        after_passes = len(self.pass_factory.issued)
        self.assertThat(
            before_passes,
            Equals(after_passes),
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
            return self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors={
                    k: v.for_call()
                    for (k, v)
                    in test_and_write_vectors_for_shares.items()
                },
                r_vector=[],
            )

        # Perform an initial write so there is something to rewrite.
        self.assertThat(
            write(),
            is_successful_write(),
            u"Server rejected a write to a new mutable slot",
        )

        # Note the prior state.
        leases_before = leases()

        # Now perform the rewrite.
        self.assertThat(
            write(),
            is_successful_write(),
            u"Server rejected rewrite of an existing mutable slot",
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
        clock=clocks(),
        write_enabler=write_enabler_secrets(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        test_and_write_vectors_for_shares=slot_test_and_write_vectors_for_shares(),
    )
    def test_mutable_rewrite_renews_expired_lease(
            self,
            storage_index,
            clock,
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
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        secrets = (write_enabler, renew_secret, cancel_secret)

        def write():
            return self.client.slot_testv_and_readv_and_writev(
                storage_index,
                secrets=secrets,
                tw_vectors={
                    k: v.for_call()
                    for (k, v)
                    in test_and_write_vectors_for_shares.items()
                },
                r_vector=[],
            )

        # See the comment in `_stat_shares_immutable_test` for an explanation
        # of clock handling and time.time monkey-patching.
        synchronize_clocks(from_clock=clock, to_clock=self.clock)
        patch = MonkeyPatch("time.time", clock.seconds)
        try:
            patch.setUp()

            # Create a share we can toy with.
            self.assertThat(write(), is_successful_write())

            # Advance time by more than a lease period so the lease is no
            # longer valid.
            clock.advance(self.server.LEASE_PERIOD.total_seconds() + 1)

            # Since we just changed the Hypothesis-supplied clock we need to
            # update the other clock (the one StorageServer is looking at)
            # too. :/
            synchronize_clocks(from_clock=clock, to_clock=self.clock)

            self.assertThat(write(), is_successful_write())
        finally:
            patch.cleanUp()

        # Not only should the write above succeed but the lease should now be
        # marked as expiring one additional lease period into the future.
        self.assertThat(
            self.server.remote_stat_shares([storage_index]),
            Equals([{
                num: ShareStat(
                    size=get_implied_data_length(
                        test_and_write_vectors_for_shares[num].write_vector,
                        test_and_write_vectors_for_shares[num].new_length,
                    ),
                    lease_expiration=int(clock.seconds() + self.server.LEASE_PERIOD.total_seconds()),
                )
                for num
                in test_and_write_vectors_for_shares
            }]),
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
        d = self.local_remote_server.callRemote(
            "slot_testv_and_readv_and_writev",
            # passes
            _encode_passes(
                self.pass_factory.get(
                    slot_testv_and_readv_and_writev_message(storage_index),
                    1,
                ),
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
