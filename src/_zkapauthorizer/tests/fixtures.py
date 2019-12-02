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

import attr

from fixtures import (
    Fixture,
    TempDir,
)

from twisted.python.filepath import (
    FilePath,
)

from allmydata.storage.server import (
    StorageServer,
)

from ..model import (
    VoucherStore,
    memory_connect,
)

class AnonymousStorageServer(Fixture):
    """
    Supply an instance of allmydata.storage.server.StorageServer which
    implements anonymous access to Tahoe-LAFS storage server functionality.

    :ivar FilePath tempdir: The path to the server's storage on the
        filesystem.

    :ivar allmydata.storage.server.StorageServer storage_server: The storage
        server.
    """
    def _setUp(self):
        self.tempdir = FilePath(self.useFixture(TempDir()).join(b"storage"))
        self.storage_server = StorageServer(
            self.tempdir.asBytesMode().path,
            b"x" * 20,
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
