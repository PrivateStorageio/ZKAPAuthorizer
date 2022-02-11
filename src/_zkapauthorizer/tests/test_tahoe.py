"""
Tests for ``_zkapauthorizer.tahoe``.
"""

from subprocess import Popen, check_output
from tempfile import mkdtemp
from time import sleep
from typing import Iterator, Optional

from attrs import define
from fixtures import TempDir
from hyperlink import DecodedURL
from testresources import TestResourceManager, setUpResources, tearDownResources
from testtools import TestCase
from testtools.matchers import Equals
from testtools.twistedsupport import AsynchronousDeferredRunTest
from twisted.internet.defer import ensureDeferred, inlineCallbacks
from twisted.python.filepath import FilePath
from yaml import safe_dump

from ..tahoe import download, upload
from .fixtures import Treq

# A plausible value for the ``retry`` parameter of ``wait_for_path``.
RETRY_DELAY = [0.3] * 100


def wait_for_path(path: FilePath, retry: Iterator[float] = RETRY_DELAY) -> None:
    """
    Wait for a file to exist at a certain path for a while.

    :raise Exception: If it does not exist by the end of the retry period.
    """
    total = 0
    for delay in retry:
        if path.exists():
            return
        sleep(delay)
        total += delay
    raise Exception(
        "expected path {!r} did not appear for {!r} seconds".format(
            path.path,
            total,
        ),
    )


def read_text(path: FilePath) -> str:
    """
    Read and decode some ASCII bytes from a file, stripping any whitespace.
    """
    return path.getContent().decode("ascii").strip()


class TemporaryDirectoryResource(TestResourceManager):
    def make(self, dependency_resources):
        return FilePath(mkdtemp())

    def isDirty(self, resource):
        # Can't detect when the directory is written to, so assume it
        # can never be reused.  We could list the directory, but that might
        # not catch it being open as a cwd etc.
        return True


@define
class TahoeStorage:
    """
    Provide a basic interface to a Tahoe-LAFS storage node child process.

    :ivar node_dir: The path to the node's directory.

    :ivar create_output: The output from creating the node.

    :ivar process: After the node is started, a handle on the child process.

    :ivar node_url: After the node is started, the root of the node's web API.

    :ivar storage_furl: After the node is started, the node's storage fURL.

    :ivar node_pubkey: After the node is started, the node's public key.
    """

    node_dir: FilePath
    create_output: Optional[str] = None
    process: Optional[Popen] = None
    node_url: Optional[FilePath] = None
    storage_furl: Optional[FilePath] = None
    node_pubkey: Optional[str] = None

    def run(self):
        """
        Create and start the node in a child process.
        """
        self.create()
        self.start()

    def create(self):
        """
        Create the node directory.
        """
        self.create_output = check_output(
            [
                "tahoe",
                "create-node",
                "--webport=tcp:port=0",
                "--hostname=127.0.0.1",
                self.node_dir.path,
            ],
            text=True,
            encoding="utf-8",
        )

    def start(self):
        """
        Start the node child process.
        """
        self.process = Popen(
            ["tahoe", "run", self.node_dir.path],
            stdout=self.node_dir.child("stdout").open("wb"),
            stderr=self.node_dir.child("stderr").open("wb"),
        )
        node_url_path = self.node_dir.child("node.url")
        wait_for_path(node_url_path)
        self.node_url = read_text(node_url_path)
        storage_furl_path = self.node_dir.descendant(["private", "storage.furl"])
        wait_for_path(storage_furl_path)
        self.storage_furl = read_text(storage_furl_path)
        node_pubkey_path = self.node_dir.child("node.pubkey")
        wait_for_path(node_pubkey_path)
        self.node_pubkey = read_text(node_pubkey_path)

    def servers_yaml_entry(self) -> dict:
        """
        Get an entry describing this storage node for a client's ``servers.yaml``
        file.
        """
        return {
            self.node_pubkey[len("pub-") :]: {
                "ann": {
                    "anonymous-storage-FURL": self.storage_furl,
                    "nickname": "storage",
                },
            },
        }


class TahoeStorageManager(TestResourceManager):
    """
    Manage a Tahoe-LAFS storage node as a ``TahoeStorage`` object.

    The node is created and run before the resource is handed out.  The
    resource is always considered "clean" so it will be re-used by as many
    tests ask for it.
    """

    resources = [("node_dir", TemporaryDirectoryResource())]

    def clean(self, storage):
        storage.process.kill()

    def make(self, dependency_resources):
        storage = TahoeStorage(**dependency_resources)
        storage.run()
        return storage


@define
class TahoeClient:
    """
    Provide a basic interface to a Tahoe-LAFS client node child process.

    :ivar node_dir: The path to the node's directory.

    :ivar storage: A representation of the storage server the node will be
        configured with.

    :ivar create_output: The output from creating the node.

    :ivar process: After the node is started, a handle on the child process.

    :ivar node_url: After the node is started, the root of the node's web API.
    """

    node_dir: FilePath
    storage: TahoeStorage
    create_output: Optional[str] = None
    process: Optional[Popen] = None
    node_url: Optional[FilePath] = None

    def run(self):
        """
        Create and start the node in a child process.
        """
        self.create()
        self.start()

    def create(self):
        """
        Create the node directory and write the necessary configuration to it.
        """
        self.create_output = check_output(
            [
                "tahoe",
                "create-node",
                "--webport=tcp:port=0",
                "--hostname=127.0.0.1",
                "--shares-needed=1",
                "--shares-total=1",
                "--shares-happy=1",
                self.node_dir.path,
            ],
            text=True,
            encoding="utf-8",
        )
        with open(
            self.node_dir.descendant(["private", "servers.yaml"]).path, "wt"
        ) as f:
            f.write(
                safe_dump({"storage": self.storage.servers_yaml_entry()}),
            )

    def start(self):
        """
        Start the node child process.
        """
        self.process = Popen(
            ["tahoe", "run", self.node_dir.path],
            stdout=self.node_dir.child("stdout").open("wb"),
            stderr=self.node_dir.child("stderr").open("wb"),
        )
        node_url_path = self.node_dir.child("node.url")
        wait_for_path(node_url_path)
        self.node_url = DecodedURL.from_text(read_text(node_url_path))


class TahoeClientManager(TestResourceManager):
    """
    Manage a Tahoe-LAFS client node as a ``TahoeClient`` object.

    The node is created and run before the resource is handed out.  The
    resource is always considered "clean" so it will be re-used by as many
    tests ask for it.
    """

    resources = [
        ("storage", TahoeStorageManager()),
        ("node_dir", TemporaryDirectoryResource()),
    ]

    def clean(self, client):
        client.process.kill()

    def make(self, dependency_resources):
        client = TahoeClient(**dependency_resources)
        client.run()
        return client


class UploadDownloadTestCase(TestCase):
    """
    Tests for ``upload`` and ``download``.
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    # Get a Tahoe-LAFS client node connected to a storage node.
    resources = [("client", TahoeClientManager())]

    def setUp(self):
        super().setUp()
        setUpResources(self, self.resources, None)
        self.addCleanup(lambda: tearDownResources(self, self.resources, None))

    @inlineCallbacks
    def test_found(self):
        """
        If the identified object can be downloaded then it is written to the given
        path.
        """
        # AsynchronousDeferredRunTest sets reactor on us.
        client = self.useFixture(Treq(self.reactor, case=self)).client()

        workdir = FilePath(self.useFixture(TempDir()).join("test_found"))
        workdir.makedirs()
        inpath = workdir.child("uploaded")
        inpath.setContent(b"abc" * 1024)
        outpath = workdir.child("downloaded")

        cap = yield ensureDeferred(upload(client, inpath, self.client.node_url))
        yield ensureDeferred(download(client, outpath, self.client.node_url, cap))

        self.assertThat(
            inpath.getContent(),
            Equals(outpath.getContent()),
        )
