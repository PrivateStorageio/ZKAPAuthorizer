"""
Tests for ``_zkapauthorizer.tahoe``.
"""

from asyncio import run
from subprocess import Popen, check_output
from sys import executable
from tempfile import mkdtemp
from time import sleep
from typing import Iterator, Optional

from attrs import define
from fixtures import TempDir
from hyperlink import DecodedURL
from testresources import TestResourceManager, setUpResources, tearDownResources
from testtools import TestCase
from testtools.matchers import Equals, Is, Not, raises
from testtools.twistedsupport import AsynchronousDeferredRunTest
from twisted.internet.defer import Deferred, ensureDeferred, inlineCallbacks
from twisted.python.filepath import FilePath
from yaml import safe_dump

from ..tahoe import async_retry, download, link, make_directory, upload
from .fixtures import Treq

# A plausible value for the ``retry`` parameter of ``wait_for_path``.
RETRY_DELAY = [0.3] * 100

# An argv prefix to use in place of `tahoe` to run the Tahoe-LAFS CLI.  This
# runs the CLI via the `__main__` so that we don't rely on `tahoe` being in
# `PATH`.
TAHOE = [executable, "-m", "allmydata"]


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

    def isDirty(self):
        # Can't detect when the directory is written to, so assume it
        # can never be reused.  We could list the directory, but that might
        # not catch it being open as a cwd etc.
        return True


def setup_exit_trigger(node_dir: FilePath) -> None:
    """
    Touch the Tahoe-LAFS exit trigger path beneath the given node directory.

    This will make sure that if we fail to clean up the node process it won't
    hang around indefinitely.  When the node starts up and sees this file, it
    will begin checking it periodically and exit if it is ever older than 2
    minutes.  Our tests should take less than 2 minutes so we don't even
    bother to update the mtime again.  If we crash somewhere then at least the
    node will exit no more than 2 minutes later.
    """
    node_dir.child("exit_trigger").touch()


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
            TAHOE
            + [
                "create-node",
                "--webport=tcp:port=0",
                "--hostname=127.0.0.1",
                self.node_dir.path,
            ],
            text=True,
            encoding="utf-8",
        )
        setup_exit_trigger(self.node_dir)

    def start(self):
        """
        Start the node child process.
        """
        eliot = ["--eliot-destination", "file:" + self.node_dir.child("log.eliot").path]
        self.process = Popen(
            TAHOE + eliot + ["run", self.node_dir.path],
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

    # This doesn't clean up the given resource - it cleans up the global
    # runtime environment in which that resource was created - by destroying
    # anything associated with it which Python will not automatically clean up
    # when the Python objects are garbage collected.
    def clean(self, storage):
        """
        Kill the storage node child process.
        """
        storage.process.kill()

    def make(self, dependency_resources):
        """
        Create and run a brand new Tahoe-LAFS storage node.
        """
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
            TAHOE
            + [
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
        setup_exit_trigger(self.node_dir)
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
        eliot = ["--eliot-destination", "file:" + self.node_dir.child("log.eliot").path]
        self.process = Popen(
            TAHOE + eliot + ["run", self.node_dir.path],
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

    # See note on TahoeStorageManager.clean
    def clean(self, client):
        """
        Kill the client node child process.
        """
        client.process.kill()

    def make(self, dependency_resources):
        """
        Create and run a brand new Tahoe-LAFS client node.
        """
        client = TahoeClient(**dependency_resources)
        client.run()
        return client


_client_manager = TahoeClientManager()


class UploadDownloadTestCase(TestCase):
    """
    Tests for ``upload`` and ``download``.
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    # Get a Tahoe-LAFS client node connected to a storage node.
    resources = [("client", _client_manager)]

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


class DirectoryTests(TestCase):
    """
    Tests for directory-related functionality.
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    # Get a Tahoe-LAFS client node connected to a storage node.
    resources = [("client", _client_manager)]

    def setUp(self):
        super().setUp()
        setUpResources(self, self.resources, None)
        self.addCleanup(lambda: tearDownResources(self, self.resources, None))
        # AsynchronousDeferredRunTest sets reactor on us.
        self.httpclient = self.useFixture(Treq(self.reactor, case=self)).client()

    @inlineCallbacks
    def test_make_directory(self):
        """
        ``make_directory`` returns a coroutine that completes with the capability
        of a new, empty directory.
        """
        dir_cap = yield Deferred.fromCoroutine(
            make_directory(self.httpclient, self.client.node_url)
        )

        # If we can download it, consider that success.
        outpath = FilePath(self.useFixture(TempDir()).join("dir_contents"))
        yield Deferred.fromCoroutine(
            download(self.httpclient, outpath, self.client.node_url, dir_cap)
        )
        self.assertThat(outpath.getContent(), Not(Equals(b"")))

    @inlineCallbacks
    def test_link(self):
        """
        ``link`` adds an entry to a directory.
        """
        tmp = FilePath(self.useFixture(TempDir()).path)
        inpath = tmp.child("source")
        inpath.setContent(b"some content")

        dir_cap = yield Deferred.fromCoroutine(
            make_directory(self.httpclient, self.client.node_url)
        )
        entry_name = "foo"
        entry_cap = yield Deferred.fromCoroutine(
            upload(self.httpclient, inpath, self.client.node_url),
        )
        yield Deferred.fromCoroutine(
            link(
                self.httpclient,
                self.client.node_url,
                dir_cap,
                entry_name,
                entry_cap,
            ),
        )

        outpath = tmp.child("destination")
        yield Deferred.fromCoroutine(
            download(
                self.httpclient,
                outpath,
                self.client.node_url,
                dir_cap,
                child_path=[entry_name],
            ),
        )

        self.assertThat(
            outpath.getContent(),
            Equals(inpath.getContent()),
        )


class AsyncRetryTests(TestCase):
    """
    Tests for ``async_retry``.
    """

    def test_success(self):
        """
        If the decorated function returns a coroutine that returns a value then
        the coroutine returned by the decorator function returns the same
        value.
        """
        result = object()

        @async_retry([lambda exc: True])
        async def decorated():
            return result

        coro = decorated()
        self.assertThat(
            run(coro),
            Is(result),
        )

    def test_not_matched_failure(self):
        """
        If the decorated function returns a coroutine that raises an exception not
        matched by any of the matchers then the coroutine returned by the
        decorator function raises the same exception.
        """

        class Exc(Exception):
            pass

        @async_retry([lambda exc: False])
        async def decorated():
            raise Exc()

        coro = decorated()
        self.assertThat(
            lambda: run(coro),
            raises(Exc),
        )

    def test_matched_failure(self):
        """
        If the decorated function returns a coroutine that raises an exception
        that is matched by one of the matchers then function is called again
        and the same logic applied to its result.
        """

        fail = True
        result = object()

        @async_retry([lambda exc: True])
        async def decorated():
            nonlocal fail
            if fail:
                fail = False
                raise Exception()
            return result

        coro = decorated()
        self.assertThat(
            run(coro),
            Is(result),
        )
