"""
``testresources``-style resources.
"""

from functools import partial
from subprocess import CalledProcessError, Popen, check_output
from sys import executable
from tempfile import mkdtemp
from time import sleep
from typing import Any, Callable, Iterable, Mapping, Optional

from allmydata.client import config_from_string
from attrs import define
from challenge_bypass_ristretto import random_signing_key
from eliottree import colored, get_theme, render_tasks, tasks_from_iterable
from hyperlink import DecodedURL
from tahoe_capabilities import CHKVerify, MDMFVerify, SSKVerify, VerifyCapability
from testresources import TestResourceManager
from testtools import TestCase
from testtools.content import Content, content_from_file
from testtools.content_type import UTF8_TEXT
from twisted.internet.defer import Deferred
from twisted.python.filepath import FilePath
from typing_extensions import TypedDict
from yaml import safe_dump

from .. import NAME
from .._json import loads
from .._storage_server import storage_index_to_dir
from .._types import JSON, ServerConfig
from ..config import Config
from .issuer import Issuer, run_issuer, stop_issuer

# An argv prefix to use in place of `tahoe` to run the Tahoe-LAFS CLI.  This
# runs the CLI via the `__main__` so that we don't rely on `tahoe` being in
# `PATH`.
TAHOE = [executable, "-m", "allmydata"]

# A plausible value for the ``retry`` parameter of ``wait_for_path``.
RETRY_DELAY = [0.3] * 100


def eliottree_from_file(path: FilePath) -> Content:
    """
    Gather Eliot logs from the given path, rendered as a tree with eliot-tree.

    The log file is not read until ``Content.iter_bytes`` resolves the
    content.  The expected usage pattern us to add this content as detail at
    the beginning of a test so that the full log is available if the test
    fails later.
    """

    def get_bytes() -> Iterable[bytes]:
        """
        Read the file and render the contents as a tree.
        """
        buf: list[str] = []
        try:
            with path.open() as f:
                render_tasks(
                    buf.append,
                    tasks_from_iterable(loads(line) for line in f),
                    human_readable=True,
                    colorize_tree=True,
                    theme=get_theme(dark_background=True, colored=colored),
                )
        except Exception as e:
            # It would be nice to send this error elsewhere but currently
            # there is no where else to send it.
            yield f"<<error reading {path.asTextMode().path}: {e}>>".encode("ascii")
        else:
            for line in buf:
                yield line.encode("utf-8")

    return Content(UTF8_TEXT, get_bytes)


class TemporaryDirectoryResource(TestResourceManager):
    def make(self, dependency_resources: dict[str, object]) -> FilePath:
        return FilePath(mkdtemp())

    def isDirty(self) -> bool:
        # Can't detect when the directory is written to, so assume it
        # can never be reused.  We could list the directory, but that might
        # not catch it being open as a cwd etc.
        return True


def read_text(path: FilePath) -> str:
    """
    Read and decode some ASCII bytes from a file, stripping any whitespace.
    """
    result = path.getContent().decode("ascii").strip()
    assert isinstance(result, str)
    return result


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
class TahoeNode:
    """
    :ivar node_dir: The path to the node's directory.

    :ivar create_output: The output from creating the node.

    :ivar process: After the node is started, a handle on the child process.

    :ivar node_url: After the node is started, the root of the node's web API.

    :ivar node_pubkey: After the node is started, the node's public key.
    """

    node_dir: FilePath
    # Unfortunately the Config type strongly prefers in-place mutation.
    # Someday, replace this with a pure function.
    customize_config: Callable[[Config], None] = lambda cfg: None
    create_output: Optional[str] = None
    process: Optional[Popen[bytes]] = None
    node_url: Optional[DecodedURL] = None
    node_pubkey: Optional[str] = None

    @property
    def node_type(self) -> str:
        raise NotImplementedError("Subclass should define node_type")

    @property
    def eliot_log_path(self) -> FilePath:
        """
        The path to the Eliot log file for this node.
        """
        return self.node_dir.child("log.eliot")  # type: ignore[no-any-return]

    @property
    def node_id(self) -> str:
        if self.node_pubkey is None:
            raise ValueError("Cannot identify Tahoe node before it starts.")
        return self.node_pubkey[len("pub-") :]

    def read_config(self) -> Config:
        """
        Read this client node's configuration file into a configuration object.
        """
        config_path = self.node_dir.child("tahoe.cfg")
        return config_from_string(
            self.node_dir.path,
            "tub.port",
            config_path.getContent(),
            fpath=config_path,
        )

    def addDetail(self, case: TestCase) -> None:
        """
        Add the Tahoe-LAFS storage node's logs as details to the given test
        case.
        """
        node_type = self.node_type

        for name in ["stdout", "stderr"]:
            case.addDetail(
                f"{node_type}-{name}",
                content_from_file(self.node_dir.child(name).path),
            )
        case.addDetail(
            f"{node_type}-eliot.log",
            eliottree_from_file(self.eliot_log_path),
        )
        case.addDetail(
            f"{node_type}-tahoe.cfg",
            content_from_file(self.node_dir.child("tahoe.cfg").path),
        )
        case.addDetail(
            f"{node_type}-create-output",
            Content(
                UTF8_TEXT,
                lambda: [self.create_output.encode("utf-8")]
                if self.create_output is not None
                else [],
            ),
        )

    def run(self) -> None:
        """
        Create and start the node in a child process.
        """
        self.create()
        self.start()

    def create_unsafely(self) -> str:
        """
        Try to create the node directory without any extra error handling.

        Use ``create`` instead.  This is for subclasses to override.
        """

    def create(self) -> None:
        """
        Create the node directory.
        """
        try:
            self.create_output = self.create_unsafely()
        except CalledProcessError as e:
            self.create_output = e.output
            raise
        setup_exit_trigger(self.node_dir)
        self.customize_config(self.read_config())

    def start(self) -> None:
        """
        Start the node child process.
        """
        eliot = [
            "--eliot-destination",
            "file:" + self.eliot_log_path.asTextMode().path,
        ]
        # Unfortunately we don't notice if this command crashes because of
        # some bug.  In that case the test will just hang and fail after
        # timing out.
        self.process = Popen(
            TAHOE + eliot + ["run", self.node_dir.asTextMode().path],
            stdout=self.node_dir.child("stdout").open("wb"),
            stderr=self.node_dir.child("stderr").open("wb"),
        )
        node_url_path = self.node_dir.child("node.url")
        wait_for_path(node_url_path)
        self.node_url = DecodedURL.from_text(read_text(node_url_path))


@define
class TahoeStorage(TahoeNode):
    """
    Provide a basic interface to a Tahoe-LAFS storage node child process.

    :ivar storage_furl: After the node is started, the node's storage fURL.
    """

    storage_furl: Optional[str] = None

    @property
    def node_type(self) -> str:
        return "storage"

    def get_share_path(self, cap: VerifyCapability, sharenum: int) -> FilePath:
        """
        Get the filesystem path to a share of an object identified by a
        certain capability which could be stored by this server.
        """
        if isinstance(cap, (CHKVerify, SSKVerify, MDMFVerify)):
            storage_index = cap.storage_index
        else:
            storage_index = cap.cap_object.storage_index
        return (  # type: ignore[no-any-return]
            self.node_dir.descendant(("storage", "shares"))
            .preauthChild(storage_index_to_dir(storage_index))
            .child(f"{sharenum}")
        )

    def get_corruption_advisories(self) -> FilePath:
        """
        Get the location of the storage server's corruption advisories
        directory.
        """
        return self.node_dir.descendant(("storage", "corruption-advisories"))  # type: ignore[no-any-return]

    def create_unsafely(self) -> str:
        """
        Create a Tahoe-LAFS storage node.
        """
        return check_output(
            TAHOE
            + [
                "create-node",
                "--webport=tcp:port=0",
                "--hostname=127.0.0.1",
                self.node_dir.asTextMode().path,
            ],
            text=True,
            encoding="utf-8",
        )

    def start(self) -> None:
        """
        Start the node child process.
        """
        super().start()
        storage_furl_path = self.node_dir.descendant(["private", "storage.furl"])
        wait_for_path(storage_furl_path)
        self.storage_furl = read_text(storage_furl_path)
        node_pubkey_path = self.node_dir.child("node.pubkey")
        wait_for_path(node_pubkey_path)
        self.node_pubkey = read_text(node_pubkey_path)

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
    def clean(self, storage: TahoeStorage) -> None:
        """
        Kill the storage node child process.
        """
        process = storage.process
        assert process is not None
        process.kill()
        process.wait()

    def make(self, dependency_resources: dict[str, Any]) -> TahoeStorage:
        """
        Create and run a brand new Tahoe-LAFS storage node.
        """
        storage = TahoeStorage(**dependency_resources)
        storage.run()
        return storage



def make_anonymous_storage_announcement(storage: TahoeStorage) -> dict:
    """
    Get an entry describing anonymous access to this storage node for a
    client's ``servers.yaml`` file.
    """
    return {
        storage.node_id: {
            "ann": {
                "anonymous-storage-FURL": storage.storage_furl,
                "nickname": "storage",
            },
        },
    }


@define
class TahoeClient(TahoeNode):
    """
    Provide a basic interface to a Tahoe-LAFS client node child process.

    :ivar make_storage_announcement: A function to construct a storage service
        announcement for a given Tahoe-LAFS storage server.  This is used to
        generate a static announcement cache containing information for the
        associate storage service, if there is one.

    :ivar storage: A representation of the storage server the node will be
        configured with.
    """

    storage: Optional[TahoeStorage] = None
    make_storage_announcement: Callable[[TahoeStorage], dict] = make_anonymous_storage_announcement

    @property
    def node_type(self) -> str:
        return "client"

    @property
    def authorization(self) -> Mapping[str, str]:
        """
        HTTP headers to submit with requests to this client to authorize use
        of its private APIs.
        """
        token = self.read_config().get_private_config("api_auth_token")
        headers = {"authorization": f"tahoe-lafs {token}"}
        return headers

    def create_unsafely(self) -> str:
        """
        Create a Tahoe-LAFS client node.
        """
        return check_output(
            TAHOE
            + [
                "create-client",
                "--webport=tcp:port=0",
                "--shares-needed=1",
                "--shares-total=1",
                "--shares-happy=1",
                self.node_dir.asTextMode().path,
            ],
            text=True,
            encoding="utf-8",
        )

    def create(self) -> None:
        """
        Create the node directory and write the necessary configuration to it.

        In addition to the inherited implementation, write the static server
        configuration.
        """
        super().create()
        if self.storage is not None:
            config = self.read_config()
            config.write_private_config(
                "servers.yaml",
                safe_dump(
                    {
                        "storage": self.make_storage_announcement(self.storage),
                    }
                ),
            )


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
    def clean(self, client: TahoeClient) -> None:
        """
        Kill the client node child process.
        """
        process = client.process
        assert process is not None
        process.kill()
        process.wait()

    def make(self, dependency_resources: dict[str, Any]) -> TahoeClient:
        """
        Create and run a brand new Tahoe-LAFS client node.
        """
        client = TahoeClient(**dependency_resources)
        client.run()
        return client


client_manager = TahoeClientManager()


def add_zkapauthz_server_section(config: Config, section: ServerConfig) -> None:
    """
    Enable the ZKAPAuthorizer plugin for a Tahoe-LAFS storage server and write
    its configuration to the correct section.

    The configuration is rewritten *in place* because that's what ``Config``
    supports.
    """
    config.set_config("storage", "plugins", NAME)
    for k, v in section.items():
        config.set_config(f"storageserver.plugins.{NAME}", k, v)


def add_zkapauthz_client_section(
    client_config: Config, storage_config: Config, issuer: Issuer
) -> None:
    """
    Enable the ZKAPAuthorizer plugin for a Tahoe-LAFS client node and write
    its configuration to the correct section.

    The configuration is rewritten *in place* because that's what ``Config``
    supports.
    """
    client_config.set_config("client", "storage.plugins", NAME)
    for k, v in issuer.client_config.items():
        client_config.set_config(f"storageclient.plugins.{NAME}", k, v)


class IssuerDependencies(TypedDict):
    """
    The dependency resources expected by ``IssuerManager``.
    """

    issuer_dir: FilePath


class IssuerManager(TestResourceManager):
    resources = [
        ("issuer_dir", TemporaryDirectoryResource()),
    ]

    def make(self, dependency_resources: IssuerDependencies) -> Issuer:
        from twisted.internet import reactor
        from twisted.internet.interfaces import IReactorTCP

        assert IReactorTCP.providedBy(reactor)

        signing_key = random_signing_key()
        issuer_path = dependency_resources["issuer_dir"]
        signing_key_path = issuer_path.child("signing.key")
        signing_key_path.setContent(signing_key.encode_base64())
        return run_issuer(reactor, signing_key_path)

    def clean(self, issuer: Issuer) -> Deferred[Any]:
        # XXX testresources doesn't know about Deferreds so this probably
        # won't get waited properly, nor failures logged very well (but it's
        # only `stopListening` so maybe it won't fail...)
        return stop_issuer(issuer)


@define
class Grid:
    storage: TahoeStorage
    client: TahoeClient

    # The resources we built it from.  testresources insists on setting these
    # on us.
    issuer: Any = None
    grid_dir: Any = None

    def addDetail(self, case: TestCase) -> None:
        self.storage.addDetail(case)
        self.client.addDetail(case)


class ZKAPTahoeGrid(TestResourceManager):
    resources = [
        ("issuer", IssuerManager()),
        ("grid_dir", TemporaryDirectoryResource()),
    ]

    def make(self, dependency_resources: Mapping[str, Any]) -> Grid:
        issuer = dependency_resources["issuer"]

        storage_dependencies = {
            "node_dir": dependency_resources["grid_dir"].child("storage"),
            "customize_config": partial(
                add_zkapauthz_server_section,
                section=issuer.server_config,
            ),
        }
        storage = TahoeStorageManager().make(storage_dependencies)

        client_dependencies = {
            "node_dir": dependency_resources["grid_dir"].child("client"),
            "storage": storage,
            "customize_config": partial(
                add_zkapauthz_client_section,
                storage_config=storage.read_config(),
                issuer=issuer,
            ),
            "make_storage_announcement": lambda storage: make_zkap_storage_announcement(issuer, storage),
        }
        client = TahoeClientManager().make(client_dependencies)

        return Grid(storage, client)

    def clean(self, grid: Grid) -> None:
        TahoeStorageManager().clean(grid.storage)
        TahoeClientManager().clean(grid.client)

def make_zkap_storage_announcement(issuer: Issuer, storage: TahoeStorage) -> dict:
    """
    Get an entry describing ZKAP-mediated access to this storage node for
    a client's ``servers.yaml`` file.
    """
    zkap_furl = storage.read_config().get_private_config(f"storage-plugin.{NAME}.furl")

    return {
        storage.node_id: {
            "ann": {
                "anonymous-storage-FURL": "pb://@tcp:/",
                "nickname": "storage",
                "storage-options": [
                    {
                        "name": NAME,
                        "storage-server-FURL": zkap_furl,
                        "allowed-public-keys": ",".join(
                            k.encode_base64().decode("ascii")
                            for k
                            in issuer.allowed_public_keys
                        ),
                        "ristretto-issuer-root-url": issuer.root_url,
                        "default-token-count": 50000,
                        "lease.crawl-interval.mean": 864000,
                        "lease.crawl-interval.range": 86400,
                        "lease.min-time-remaining": 0,
                        "pass-value": 1000000,
                     },
                ],
            },
        },
    }
