"""
Tests for ``_zkapauthorizer.tahoe``.
"""

from subprocess import Popen, check_call
from tempfile import mkdtemp
from time import sleep
from typing import Optional

from attrs import define
from fixtures import TempDir
from hyperlink import DecodedURL
from testresources import TestResourceManager, setUpResources, tearDownResources
from testtools import TestCase
from testtools.matchers import Equals
from testtools.twistedsupport import AsynchronousDeferredRunTest
from treq.client import HTTPClient
from twisted.internet.defer import Deferred, ensureDeferred, inlineCallbacks
from twisted.python.filepath import FilePath
from twisted.web.client import Agent, HTTPConnectionPool
from yaml import safe_dump

from ..tahoe import download, upload


def wait_for(path):
    while not path.exists():
        print(f"{path.path} does not exist")
        sleep(0.3)


@define
class TahoeStorage:
    node_dir: FilePath
    process: Optional[Popen] = None
    node_url: Optional[FilePath] = None
    storage_furl: Optional[FilePath] = None
    node_pubkey: Optional[str] = None

    def run(self):
        check_call(
            [
                "tahoe",
                "create-node",
                "--webport=tcp:port=0",
                "--hostname=127.0.0.1",
                self.node_dir.path,
            ]
        )
        self.process = Popen(["tahoe", "run", self.node_dir.path])
        node_url_path = self.node_dir.child("node.url")
        wait_for(node_url_path)
        self.node_url = node_url_path.getContent().decode("ascii").strip()
        storage_furl_path = self.node_dir.descendant(["private", "storage.furl"])
        wait_for(storage_furl_path)
        self.storage_furl = storage_furl_path.getContent().decode("ascii").strip()
        node_pubkey_path = self.node_dir.child("node.pubkey")
        wait_for(node_pubkey_path)
        self.node_pubkey = node_pubkey_path.getContent().decode("ascii").strip()

    def servers_yaml_entry(self):
        return {
            self.node_pubkey[len("pub-") :]: {
                "ann": {
                    "anonymous-storage-FURL": self.storage_furl,
                    "nickname": "storage",
                },
            },
        }


class TemporaryDirectoryResource(TestResourceManager):
    def clean(self, resource):
        resource.remove()

    def make(self, dependency_resources):
        return FilePath(mkdtemp())

    def isDirty(self, resource):
        # Can't detect when the directory is written to, so assume it
        # can never be reused.  We could list the directory, but that might
        # not catch it being open as a cwd etc.
        return True


class TahoeStorageManager(TestResourceManager):
    resources = [("node_dir", TemporaryDirectoryResource())]

    def clean(self, storage):
        storage.process.kill()

    def make(self, dependency_resources):
        storage = TahoeStorage(**dependency_resources)
        storage.run()
        return storage


@define
class TahoeClient:
    node_dir: FilePath
    storage: Optional[TahoeStorage] = None
    process: Optional[Popen] = None
    node_url: Optional[FilePath] = None

    def run(self):
        check_call(
            [
                "tahoe",
                "create-node",
                "--webport=tcp:port=0",
                "--hostname=127.0.0.1",
                "--shares-needed=1",
                "--shares-total=1",
                "--shares-happy=1",
                self.node_dir.path,
            ]
        )
        with open(
            self.node_dir.descendant(["private", "servers.yaml"]).path, "wt"
        ) as f:
            f.write(
                safe_dump({"storage": self.storage.servers_yaml_entry()}),
            )
        self.process = Popen(["tahoe", "run", self.node_dir.path])
        node_url_path = self.node_dir.child("node.url")
        wait_for(node_url_path)
        self.node_url = DecodedURL.from_text(
            node_url_path.getContent().decode("ascii").strip()
        )


class TahoeClientManager(TestResourceManager):
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


class DownloadTestCase(TestCase):
    """
    Tests for ``download``.
    """

    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

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
        sleep(1)
        from twisted.internet import reactor

        pool = HTTPConnectionPool(reactor, persistent=False)
        self.addCleanup(pool.closeCachedConnections)

        treq = HTTPClient(Agent(reactor, pool))

        workdir = FilePath(self.useFixture(TempDir()).join("test_found"))
        workdir.makedirs()

        inpath = workdir.child("uploaded")
        inpath.setContent(b"abc" * 1024)

        outpath = workdir.child("downloaded")
        cap = yield ensureDeferred(upload(treq, inpath, self.client.node_url))
        yield ensureDeferred(download(treq, outpath, self.client.node_url, cap))
        self.assertThat(
            inpath.getContent(),
            Equals(outpath.getContent()),
        )
