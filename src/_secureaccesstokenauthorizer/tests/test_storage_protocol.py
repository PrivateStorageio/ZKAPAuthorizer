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
import attr

from fixtures import (
    Fixture,
    TempDir,
    MonkeyPatch,
)
from testtools import (
    TestCase,
)
from testtools.matchers import (
    Equals,
    HasLength,
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
    tuples,
)

from twisted.python.filepath import (
    FilePath,
)
from twisted.internet.defer import (
    execute,
)

from foolscap.referenceable import (
    LocalReferenceable,
)

from allmydata.storage.server import (
    StorageServer,
)

from .strategies import (
    storage_indexes,
    lease_renew_secrets,
    lease_cancel_secrets,
    sharenums,
    sharenum_sets,
    sizes,
)

from ..api import (
    SecureAccessTokenAuthorizerStorageServer,
    SecureAccessTokenAuthorizerStorageClient,
)

def bytes_for_share(sharenum, size):
    """
    Generate marginally distinctive bytes of a certain length for the given
    share number.
    """
    if 0 <= sharenum <= 255:
        return (unichr(sharenum) * size).encode("latin-1")
    raise ValueError("Sharenum must be between 0 and 255 inclusive.")


class AnonymousStorageServer(Fixture):
    def _setUp(self):
        self.tempdir = self.useFixture(TempDir()).join(b"storage")
        self.storage_server = StorageServer(
            self.tempdir,
            b"x" * 20,
        )


@attr.s
class LocalRemote(object):
    _referenceable = attr.ib()

    def callRemote(self, methname, *args, **kwargs):
        return execute(
            getattr(self._referenceable, "remote_" + methname),
            *args,
            **kwargs
        )


class ShareTests(TestCase):
    """
    Tests for interaction with shares.
    """
    def setUp(self):
        super(ShareTests, self).setUp()
        self.canary = LocalReferenceable(None)
        self.anonymous_storage_server = self.useFixture(AnonymousStorageServer()).storage_server

        def get_tokens():
            return [u"x"]

        self.server = SecureAccessTokenAuthorizerStorageServer(
            self.anonymous_storage_server,
        )
        self.local_remote_server = LocalRemote(self.server)
        self.client = SecureAccessTokenAuthorizerStorageClient(
            get_rref=lambda: self.local_remote_server,
            get_tokens=get_tokens,
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
            bucket.remote_write(0, bytes_for_share(sharenum, size)),
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
        sharenum=sharenums(),
        size=sizes(),
    )
    def test_add_lease(self, storage_index, renew_secrets, cancel_secret, sharenum, size):
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
            {sharenum},
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
        [(_, leases)] = get_leases(self.server, storage_index).items()
        self.assertThat(leases, HasLength(2))

    @given(
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenum=sharenums(),
        size=sizes(),
    )
    def test_renew_lease(self, storage_index, renew_secret, cancel_secret, sharenum, size):
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
            {sharenum},
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

        # Based on Tahoe-LAFS' hard-coded renew time.
        RENEW_INTERVAL = 60 * 60 * 24 * 31

        [(_, [lease])] = get_leases(self.server, storage_index).items()
        self.assertThat(
            lease.get_expiration_time(),
            Equals(int(now + RENEW_INTERVAL)),
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
                u"immutable",
                storage_index,
                sharenum,
                u"the bits look bad",
            ),
        )
        self.assertThat(
            FilePath(self.anonymous_storage_server.corruption_advisory_dir).children(),
            HasLength(1),
        )


def write_toy_shares(
        storage_server,
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        size,
        canary,
):
    """
    Write some immutable shares to the given storage server.

    :param allmydata.storage.server.StorageServer storage_server:
    :param bytes storage_index:
    :param bytes renew_secret:
    :param bytes cancel_secret:
    :param set[int] sharenums:
    :param int size:
    :param IRemoteReference canary:
    """
    _, allocated = storage_server.remote_allocate_buckets(
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        size,
        canary=canary,
    )
    for (sharenum, writer) in allocated.items():
        writer.remote_write(0, bytes_for_share(sharenum, size))
        writer.remote_close()


def get_leases(storage_server, storage_index):
    """
    Get all leases for all shares of the given storage index on the given
    server.

    :param StorageServer storage_server: The storage server on which to find
        the information.

    :param bytes storage_index: The storage index for which to look up shares.

    :return dict[int, list[LeaseInfo]]: The lease information for each share.
    """
    # It's hard to assert much about the lease without knowing about *some*
    # implementation details of the storage server.  I prefer to know Python
    # API details rather than on-disk format details.
    return {
        sharenum: list(reader._share_file.get_leases())
        for (sharenum, reader)
        in storage_server.remote_get_buckets(storage_index).items()
    }


def cleanup_storage_server(storage_server):
    """
    Delete all of the shares held by the given storage server.

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server with some on-disk shares to delete.
    """
    starts = [
        FilePath(storage_server.sharedir),
        FilePath(storage_server.corruption_advisory_dir),
    ]
    for start in starts:
        for p in start.walk():
            if p is not start:
                p.remove()
