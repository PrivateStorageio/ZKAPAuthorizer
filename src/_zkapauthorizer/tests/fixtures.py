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

from __future__ import (
    absolute_import,
)

from base64 import (
    b64encode,
)

import attr

from fixtures import (
    Fixture,
    TempDir,
)

from twisted.python.filepath import (
    FilePath,
)
from twisted.internet.task import (
    Clock,
)
from allmydata.storage.server import (
    StorageServer,
)

from ..model import (
    VoucherStore,
    open_and_initialize,
    memory_connect,
)
from ..controller import (
    DummyRedeemer,
    PaymentController,
)

@attr.s
class AnonymousStorageServer(Fixture):
    """
    Supply an instance of allmydata.storage.server.StorageServer which
    implements anonymous access to Tahoe-LAFS storage server functionality.

    :ivar FilePath tempdir: The path to the server's storage on the
        filesystem.

    :ivar allmydata.storage.server.StorageServer storage_server: The storage
        server.

    :ivar twisted.internet.task.Clock clock: The ``IReactorTime`` provider to
        supply to ``StorageServer`` for its time-checking needs.
    """
    clock = attr.ib()

    def _setUp(self):
        self.tempdir = FilePath(self.useFixture(TempDir()).join(b"storage"))
        if allmydata_version >= "1.16.":
            # This version of Tahoe adds a new StorageServer argument for
            # controlling time.
            timeargs = {"get_current_time": self.clock.seconds}
        else:
            # Older versions just use time.time() and there's not much we can
            # do _here_.  Code somewhere else will have to monkey-patch that
            # to control things.
            timeargs = {}

        self.storage_server = StorageServer(
            self.tempdir.asBytesMode().path,
            b"x" * 20,
            **timeargs
        )


@attr.s
class TemporaryVoucherStore(Fixture):
    """
    Create a ``VoucherStore`` in a temporary directory associated with the
    given test case.

    :ivar get_config: A function like the one built by ``tahoe_configs``.
    :ivar get_now: A no-argument callable that returns a datetime giving a
        time to consider as "now".

    :ivar store: A newly created temporary store.
    """
    get_config = attr.ib()
    get_now = attr.ib()

    def _setUp(self):
        self.tempdir = self.useFixture(TempDir())
        self.config = self.get_config(self.tempdir.join(b"node"), b"tub.port")
        self.store = VoucherStore.from_node_config(
            self.config,
            self.get_now,
            memory_connect,
        )


@attr.s
class ConfiglessMemoryVoucherStore(Fixture):
    """
    Create a ``VoucherStore`` backed by an in-memory database and with no
    associated Tahoe-LAFS configuration or node.

    This is like ``TemporaryVoucherStore`` but faster because it skips the
    Tahoe-LAFS parts.
    """
    get_now = attr.ib()
    _public_key = attr.ib(default=b64encode(b"A" * 32).decode("utf-8"))
    redeemer = attr.ib(default=None, init=False)

    def __attrs_post_init__(self):
        self.redeemer = DummyRedeemer(self._public_key)

    def _setUp(self):
        here = FilePath(u".")
        self.store = VoucherStore(
            pass_value=2 ** 15,
            database_path=here,
            now=self.get_now,
            connection=open_and_initialize(here, memory_connect),
        )

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
            clock=Clock(),
        ).redeem(
            voucher,
        )
