"""
``testresources``-style resources.
"""

from subprocess import Popen, check_output
from sys import executable
from tempfile import mkdtemp
from time import sleep
from typing import Iterable, Optional

from allmydata.client import config_from_string
from attrs import define
from hyperlink import DecodedURL
from testresources import TestResourceManager
from twisted.python.filepath import FilePath
from yaml import safe_dump

from ..config import Config

# An argv prefix to use in place of `tahoe` to run the Tahoe-LAFS CLI.  This
# runs the CLI via the `__main__` so that we don't rely on `tahoe` being in
# `PATH`.
TAHOE = [executable, "-m", "allmydata"]

# A plausible value for the ``retry`` parameter of ``wait_for_path``.
RETRY_DELAY = [0.3] * 100


class TemporaryDirectoryResource(TestResourceManager):
    def make(self, dependency_resources):
        return FilePath(mkdtemp())

    def isDirty(self):
        # Can't detect when the directory is written to, so assume it
        # can never be reused.  We could list the directory, but that might
        # not catch it being open as a cwd etc.
        return True


def read_text(path: FilePath) -> str:
    """
    Read and decode some ASCII bytes from a file, stripping any whitespace.
    """
    return path.getContent().decode("ascii").strip()


def wait_for_path(path: FilePath, retry: Iterable[float] = RETRY_DELAY) -> None:
    """
    Wait for a file to exist at a certain path for a while.

    :raise Exception: If it does not exist by the end of the retry period.
    """
    total: float = 0
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
        if self.node_pubkey is not None:
            return {
                self.node_pubkey[len("pub-") :]: {
                    "ann": {
                        "anonymous-storage-FURL": self.storage_furl,
                        "nickname": "storage",
                    },
                },
            }
        raise ValueError("Cannot get servers.yaml before starting.")


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
        storage.process.wait()

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

    def read_config(self) -> Config:
        """
        Read this client node's configuration file into a configuration object.
        """
        return config_from_string(
            self.node_dir.path,
            "tub.port",
            self.node_dir.child("tahoe.cfg").getContent(),
        )

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
        # Unfortunately we don't notice if this command crashes because of
        # some bug.  In that case the test will just hang and fail after
        # timing out.
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
        client.process.wait()

    def make(self, dependency_resources):
        """
        Create and run a brand new Tahoe-LAFS client node.
        """
        client = TahoeClient(**dependency_resources)
        client.run()
        return client


client_manager = TahoeClientManager()
