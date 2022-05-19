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
Common fixtures to let the test suite focus on application logic.
"""

import gc
from base64 import b64encode
from datetime import datetime
from typing import Any, Callable, Generator

import attr
from allmydata.storage.server import StorageServer
from attrs import define, field
from fixtures import Fixture, TempDir
from testtools import TestCase
from treq.client import HTTPClient
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.interfaces import IReactorTime
from twisted.internet.task import Clock, deferLater
from twisted.python.filepath import FilePath
from twisted.web.client import Agent, HTTPConnectionPool

from .._plugin import open_store
from ..config import CONFIG_DB_NAME, EmptyConfig, TahoeConfig
from ..controller import DummyRedeemer, IRedeemer, PaymentController
from ..model import memory_connect
from ..replicate import with_replication


@attr.s(auto_attribs=True)
class AnonymousStorageServer(Fixture):
    """
    Supply an instance of allmydata.storage.server.StorageServer which
    implements anonymous access to Tahoe-LAFS storage server functionality.

    :ivar tempdir: The path to the server's storage on the filesystem.

    :ivar storage_server: The protocol-agnostic storage server backend.

    :ivar clock: The ``IReactorTime`` provider to supply to ``StorageServer``
        for its time-checking needs.
    """

    clock: Clock = attr.ib()

    tempdir: FilePath = attr.ib(default=None)
    storage_server: StorageServer = attr.ib(default=None)

    def _setUp(self):
        self.tempdir = FilePath(self.useFixture(TempDir()).join("storage"))
        self.storage_server = StorageServer(
            self.tempdir.path,
            b"x" * 20,
            clock=self.clock,
        )


def _get_empty_config(rootpath: str, portnumfile: str) -> TahoeConfig:
    """
    Construct an empty Tahoe configuration object.

    :param rootpath: The path of the node directory the configuration will
        use.
    """
    return EmptyConfig(FilePath(rootpath))


@define
class TemporaryVoucherStore(Fixture):
    """
    Create a ``VoucherStore`` in a temporary directory associated with the
    given test case.

    :ivar get_config: A function like the one built by ``tahoe_configs``.
    :ivar get_now: A no-argument callable that returns a datetime giving a
        time to consider as "now".

    :ivar store: A newly created temporary store.
    """

    get_now: Callable[[], datetime]
    get_config: Callable[[str, str], TahoeConfig] = _get_empty_config
    _public_key: str = b64encode(b"A" * 32).decode("utf-8")
    redeemer: IRedeemer = field(init=False)

    @redeemer.default
    def _redeemer_default(self):
        return DummyRedeemer(self._public_key)

    def _setUp(self):
        self.tempdir = self.useFixture(TempDir())
        self.config = self.get_config(self.tempdir.join("node"), "tub.port")
        db_path = FilePath(self.config.get_private_path(CONFIG_DB_NAME))
        self.store = open_store(
            self.get_now,
            with_replication(memory_connect(db_path.path), False),
            self.config,
        )
        self.addCleanup(self._cleanUp)

    def _cleanUp(self):
        """
        Drop the reference to the ``VoucherStore`` so the underlying SQLite3
        connection can close.
        """
        self.store = None

    def redeem(self, voucher, num_passes):
        """
        Redeem a voucher for some passes.

        :return: A ``Deferred`` that fires with the redemption result.
        """
        return PaymentController(
            self.store,
            self.redeemer,
            # Have to pass it here or to redeem, doesn't matter which.
            default_token_count=num_passes,
            # No value in splitting it into smaller groups in this case.
            # Doing so only complicates the test by imposing a different
            # minimum token count requirement (can't have fewer tokens
            # than groups).
            num_redemption_groups=1,
            allowed_public_keys={self._public_key},
            clock=Clock(),
        ).redeem(
            voucher,
        )


@define
class Treq(Fixture):
    """
    Offer a facility for creating an ``HTTPClient`` which does real I/O using
    a Twisted reactor and is automatically cleaned up.
    """

    reactor: IReactorTime

    # We require a TestCase that supports asynchronous cleanups because
    # Fixtures can't handle them natively.
    case: TestCase

    pool: HTTPConnectionPool = field()

    @pool.default
    def _pool(self):
        return HTTPConnectionPool(self.reactor)

    def _setUp(self):
        # Make sure connections from the connection pool are cleaned up at the
        # end of the test.
        self.case.addCleanup(self._cleanup)

    def client(self) -> HTTPClient:
        """
        Get a new client object.
        """
        return HTTPClient(Agent(self.reactor, self.pool))

    @inlineCallbacks
    def _cleanup(self) -> Generator[Deferred[Any], Any, None]:
        """
        Clean up reactor event-sources allocated by ``HTTPConnectionPool``.
        """
        # Close any connections that are idling in the connection pool.
        yield self.pool.closeCachedConnections()

        # There may be connections which were *just* finished with.  Their
        # `loseConnection` has been called but the connection hasn't actually been
        # lost yet.  If their buffers are actually empty then they will close
        # after the reactor gets another look at them.  Unfortunately it is
        # unspecified how long after `loseConnection` the connection will actually
        # be lost (the protocol is told via its connectionLost method but the
        # connection pool does not expose that information to us).  Empirically, a
        # couple of reactor iterations (or whatever the equivalent is on this
        # reactor) seems to be enough.  If it's not, sorry.
        yield deferLater(self.reactor, 0, lambda: None)
        yield deferLater(self.reactor, 0, lambda: None)


class DetectLeakedDescriptors(Fixture):
    """
    Check for file descriptors that are open at clean up time that were not
    open at set up time and cause the test to fail if any are found.
    """

    blacklist_filenames = {
        "privatestorageio-zkapauthz-v1.sqlite3",
        "privatestorageio-zkapauthz-v1.sqlite3 (deleted)",
    }

    def _setUp(self):
        fdpath = FilePath("/proc/self/fd")
        if fdpath.isdir():
            # If it exists, we can inspect it to learn about open file
            # descriptors.  If it doesn't, it's a bit harder and we don't
            # bother for now.
            self._before = fdpath.children()
            self.addCleanup(self._cleanup)

    def _cleanup(self):
        def get_leaked():
            after = FilePath("/proc/self/fd").children()
            return {
                e.realpath()
                for e in set(after) - set(self._before)
                if e.realpath().basename() in self.blacklist_filenames
            }

        leaked = get_leaked()
        if leaked:
            # VoucherStore hangs off _Client which participates in a set of
            # impressively complex cyclic references.  The reference counting
            # collector will not clean it up so we will *always* see open file
            # descriptors if we don't trigger the cycle collector.
            #
            # Garbage collection is expensive though and a lot of the test
            # suite doesn't make any VoucherStores or _Clients.  So only
            # trigger this if we have reason to believe something might have
            # leaked.
            gc.collect()

            leaked = get_leaked()
            if leaked:
                raise ValueError(leaked)
