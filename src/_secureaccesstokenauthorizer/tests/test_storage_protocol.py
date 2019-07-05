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

from struct import (
    unpack,
)

from fixtures import (
    Fixture,
    TempDir,
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


class ImmutableTests(TestCase):
    """
    Tests for interaction with immutable shares.
    """
    def setUp(self):
        super(ImmutableTests, self).setUp()
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
    def test_create(self, storage_index, renew_secret, cancel_secret, sharenums, size):
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
        _, allocated = self.anonymous_storage_server.remote_allocate_buckets(
            storage_index,
            add_lease_secret,
            cancel_secret,
            {sharenum},
            size,
            canary=self.canary,
        )
        [(_, writer)] = allocated.items()
        writer.remote_write(0, bytes_for_share(sharenum, size))
        writer.remote_close()

        extract_result(
            self.client.add_lease(
                storage_index,
                renew_lease_secret,
                cancel_secret,
            ),
        )

        # It's hard to assert much about the lease without knowing about
        # *some* implementation details of the storage server.  I prefer to
        # know Python API details rather than on-disk format details.
        [(_, reader)] = self.server.remote_get_buckets(storage_index).items()
        leases = list(reader._share_file.get_leases())
        self.assertThat(leases, HasLength(2))


def cleanup_storage_server(storage_server):
    """
    Delete all of the shares held by the given storage server.

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server with some on-disk shares to delete.
    """
    start = FilePath(storage_server.sharedir)
    for p in start.walk():
        if p is not start:
            p.remove()
