from __future__ import (
    absolute_import,
)

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
