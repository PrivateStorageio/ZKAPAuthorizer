"""
A library for interacting with a Tahoe-LAFS node.
"""

from collections.abc import Awaitable
from functools import wraps
from hashlib import sha256
from json import loads
from tempfile import mkdtemp
from typing import IO, Any, Callable, List, Optional, TypeVar, Union, cast

import treq
from allmydata.util.base32 import b2a as b32encode
from attrs import Factory, define, field, frozen
from hyperlink import DecodedURL
from tahoe_capabilities import (
    CHKRead,
    CHKVerify,
    DirectoryReadCapability,
    NotRecognized,
    ReadCapability,
    SSKDirectoryWrite,
    SSKWrite,
    capability_from_string,
    danger_real_capability_string,
    digested_capability_string,
    is_directory,
    is_write,
    readable_from_string,
    readonly_directory_from_string,
    writeable_directory_from_string,
    writeable_from_string,
)
from treq.client import HTTPClient
from twisted.internet.error import ConnectionRefusedError
from twisted.internet.interfaces import IReactorTCP
from twisted.python.filepath import FilePath
from twisted.web.client import Agent
from typing_extensions import ParamSpec
from zope.interface import Interface, implementer

from ._types import CapStr
from .config import Config, read_node_url
from .storage_common import (
    get_configured_shares_needed,
    get_configured_shares_total,
    required_passes,
    share_size_for_data,
)

# An object which can get a readable byte stream
DataProvider = Callable[[], IO[bytes]]


@frozen
class DirectoryEntry:
    """
    An entry in a directory.

    :ivar kind: Either ``"filenode"`` or ``"dirnode"``.
    :ivar size: The size of the entry's data, in bytes.
    """

    kind: str
    size: int


@frozen
class ShareEncoding:
    """
    :ivar needed: The number of shares required to re-assemble the ciphertext.

    :ivar total: The total number of shares produced the ciphertext has been
        encoded in to.
    """

    needed: int
    total: int


_T = TypeVar("_T")
_P = ParamSpec("_P")


def async_retry(
    matchers: list[Callable[[Exception], bool]]
) -> Callable[[Callable[_P, Awaitable[_T]]], Callable[_P, Awaitable[_T]]]:
    """
    Decorate a function with automatic retry behavior for certain cases.

    :param matchers: A list of objects with a ``match`` method.  If any of
        these return ``True`` for an exception raised by the decorated
        function then the decorated function will be called again.
    """

    def retry_decorator(f: Callable[_P, Awaitable[_T]]) -> Callable[_P, Awaitable[_T]]:
        @wraps(f)
        async def decorated(*a: _P.args, **kw: _P.kwargs) -> _T:
            while True:
                try:
                    result = await f(*a, **kw)
                except Exception as e:
                    if any(match(e) for match in matchers):
                        continue
                    raise
                else:
                    return result

        return decorated

    return retry_decorator


def _not_enough_servers(exc: Exception, /) -> bool:
    """
    Match the exception that is raised when the Tahoe-LAFS client node is not
    connected to enough servers to satisfy the encoding configuration.
    """
    return isinstance(exc, TahoeAPIError) and (
        "allmydata.interfaces.NoServersError" in str(exc)
        or "allmydata.mutable.common.NotEnoughServersError" in str(exc)
    )


def _connection_refused(exc: Exception, /) -> bool:
    """
    Match the exception that is raised when the Tahoe-LAFS client node does
    not accept the API call connection attempt.
    """
    # Note this is the exception from Twisted, not the builtin exception.
    return isinstance(exc, ConnectionRefusedError)


def _scrub_cap(cap: str) -> str:
    """
    Return a new string that cannot be used to recover the input string but
    can usually be distinguished from the scrubbed version of a different
    input string.
    """
    scrubbed = b32encode(sha256(cap.encode("ascii")).digest())[:6]
    return f"URI:SCRUBBED:{scrubbed}"


def _scrub_caps_from_url(url: DecodedURL) -> DecodedURL:
    """
    Return a new URL that is like ``url`` but has all capability strings in it
    replaced with distinct but unusable substitutes.
    """
    # One form is like /uri/<cap>
    if (
        len(url.path) > 1
        and url.path[0] == "uri"
        and not url.path[1].startswith("URI:SCRUBBED:")
    ):
        cap = url.path[1]
        new = url.replace(path=(url.path[0], _scrub_cap(cap)) + tuple(url.path[2:]))
        return new

    # That is the only form we use at the moment, in fact.
    return url


@define(auto_exc=False)
class TahoeAPIError(Exception):
    """
    Some error was reported from a Tahoe-LAFS HTTP API.

    :ivar status: The HTTP response status code.
    :ivar body: The HTTP response body.
    """

    method: str
    url: DecodedURL = field(converter=_scrub_caps_from_url)
    status: int
    body: str


class NotWriteableError(Exception):
    """
    An attempt was made to write to something which is not writeable.
    """


class NotADirectoryError(Exception):
    """
    An attempt was made to treat a non-directory as a directory.
    """


_common_tahoe_errors = [_not_enough_servers, _connection_refused]


@async_retry(_common_tahoe_errors)
async def upload_bytes(
    client: HTTPClient,
    get_data_provider: DataProvider,
    api_root: DecodedURL,
) -> ReadCapability:
    """
    Upload the given data and return the resulting capability.

    If not enough storage servers are reachable then the upload is
    automatically retried.

    :param client: An HTTP client to use to make requests to the Tahoe-LAFS
        HTTP API to perform the upload.

    :param get_data_provider: A callable that returns a BinaryIO ready
        to provide the bytes to upload. This isn't a BinaryIO _directly_
        because we might re-try the operation, in which case we need a new
        stream.

    :param api_root: The location of the root of the Tahoe-LAFS HTTP API to
        use to perform the upload.  This should typically be the ``node.url``
        value from a Tahoe-LAFS client node.

    :return: If the upload is successful then the capability of the uploaded
        data is returned.

    :raise: If there is a problem uploading the data -- except for
        unavailability of storage servers -- then some exception is raised.
    """
    uri = api_root.child("uri")
    data = get_data_provider()
    resp = await client.put(uri, data)
    body = await treq.content(resp)
    content = body.decode("utf-8")
    if resp.code in (200, 201):
        return readable_from_string(content)
    raise TahoeAPIError("put", uri, resp.code, content)


async def download(
    client: HTTPClient,
    outpath: FilePath,
    api_root: DecodedURL,
    cap: ReadCapability,
) -> None:
    """
    Download the object identified by the given capability to the given path.

    :param client: An HTTP client to use to make requests to the Tahoe-LAFS
        HTTP API to perform the upload.

    :param outpath: The path to the regular file to which the downloaded
        content will be written.  The content will be written to a temporary
        file next to this one during download and then moved to this location
        at the end.

    :param api_root: The location of the root of the Tahoe-LAFS HTTP API to
        use to perform the upload.  This should typically be the ``node.url``
        value from a Tahoe-LAFS client node.

    :param cap: The capability of the data to download.

    :raise: If there is a problem downloading the data then some exception is
        raised.
    """
    outtemp = outpath.temporarySibling()  # type: ignore[no-untyped-call]

    uri = api_root.child("uri").child(danger_real_capability_string(cap))

    resp = await client.get(uri)
    if resp.code == 200:
        with outtemp.open("w") as f:
            await treq.collect(resp, f.write)
        outtemp.moveTo(outpath)
    else:
        content = (await treq.content(resp)).decode("utf-8")
        raise TahoeAPIError("get", uri, resp.code, content)


@frozen
class FileNode:
    size: int
    ro_uri: ReadCapability


@frozen
class DirectoryNode:
    ro_uri: DirectoryReadCapability


_DirectoryEntry = Union[FileNode, DirectoryNode]
_DirectoryListing = dict[str, _DirectoryEntry]


@async_retry(_common_tahoe_errors)
async def list_directory(
    client: HTTPClient,
    api_root: DecodedURL,
    dir_cap: str,
) -> _DirectoryListing:
    """
    Read the direct children of a directory.
    """
    if not dir_cap.startswith("URI:DIR2"):
        raise ValueError(f"Cannot list a non-directory capability ({dir_cap[:7]})")

    uri = api_root.child("uri").child(dir_cap).child("").add("t", "json")
    resp = await client.get(uri)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code == 200:
        kind, details = loads(content)

        def filenode(entry: dict[str, Any]) -> FileNode:
            return FileNode(entry["size"], readable_from_string(entry["ro_uri"]))

        def dirnode(entry: dict[str, Any]) -> DirectoryNode:
            return DirectoryNode(readonly_directory_from_string(entry["ro_uri"]))

        r: _DirectoryListing = {}
        for (name, (entry_kind, entry)) in details["children"].items():
            if entry_kind == "filenode":
                r[name] = filenode(entry)
            else:
                r[name] = dirnode(entry)
        return r

    raise TahoeAPIError("get", uri, resp.code, content)


@async_retry(_common_tahoe_errors)
async def make_directory(
    client: HTTPClient,
    api_root: DecodedURL,
) -> str:
    """
    Create a new mutable directory and return the write capability string.
    """
    uri = api_root.child("uri").add("t", "mkdir")
    resp = await client.post(uri)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code == 200:
        return cast(str, content)
    raise TahoeAPIError("post", uri, resp.code, content)


@async_retry(_common_tahoe_errors)
async def link(
    client: HTTPClient,
    api_root: DecodedURL,
    dir_cap: str,
    entry_name: str,
    entry_cap: str,
) -> None:
    """
    Link an object into a directory.

    :param dir_cap: The capability string of the directory in which to create
        the link.

    :param entry_cap: The capability string of the object to link in to the
        directory.
    """
    uri = api_root.child("uri").child(dir_cap).child(entry_name).add("t", "uri")
    resp = await client.put(uri, data=entry_cap.encode("ascii"))
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code == 200:
        return None

    if resp.code == 500 and "allmydata.mutable.common.NotWriteableError" in content:
        raise NotWriteableError()

    raise TahoeAPIError("put", uri, resp.code, content)


@async_retry(_common_tahoe_errors)
async def unlink(
    client: HTTPClient,
    api_root: DecodedURL,
    dir_cap: str,
    entry_name: str,
) -> None:
    """
    Unink an object from a directory.

    :param dir_cap: The capability string of the directory in which to create
        the link.

    :param entry_name: The name of the entry to delete.

    :raise NotWriteableError: If the given directory capability is a read-only
        capability.

    :raise NotDirectoryError: If the given capability is not a directory
        capability at all.
    """
    uri = api_root.child("uri").child(dir_cap).child(entry_name)
    resp = await client.delete(uri)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code == 200:
        return None

    if resp.code == 500 and "allmydata.mutable.common.NotWriteableError" in content:
        raise NotWriteableError()
    elif resp.code == 400 and "Files have no children named" in content:
        raise NotADirectoryError()

    raise TahoeAPIError("delete", uri, resp.code, content)


@frozen
class TahoeConfig:
    """
    An abstract interface to the configuration of a Tahoe-LAFS client node.

    :ivar encoding: The node's default erasure encoding parameters.
    """

    encoding: ShareEncoding


class ITahoeClient(Interface):
    """
    A simple Tahoe-LAFS client interface.
    """

    def get_config() -> TahoeConfig:
        """
        Get an abstract representation of this client node's configuration.
        """

    def get_private_path(name: str) -> FilePath:
        """
        Get the path to a file in the client node's private directory.
        """

    async def download(
        outpath: FilePath,
        cap: ReadCapability,
    ) -> None:
        """
        Download the contents of an object to a given local path.
        """

    async def upload(data_provider: DataProvider) -> ReadCapability:
        """
        Upload some data, creating a new object, and returning a capability for
        it.

        :param get_data_provider: A callable which returns the data to be
            uploaded.  This may be called more than once in case a retry is
            required.
        """

    async def make_directory() -> CapStr:
        """
        Create a new, empty, mutable directory.
        """

    async def link(dir_cap: CapStr, entry_name: str, entry_cap: CapStr) -> None:
        """
        Link an object into a directory.

        :param dir_cap: The capability of the directory to link into.
        :param entry_name: The name of the new link.
        :param entry_cap: The capability of the object to link in.
        """

    async def unlink(dir_cap: CapStr, entry_name: str) -> None:
        """
        Delete an object out of a directory.

        :param dir_cap: The capability of the directory to unlink from.
        :param entry_name: The name of the entry to remove.
        """

    async def list_directory(dir_cap: CapStr) -> _DirectoryListing:
        """
        List the entries linked into a directory.
        """


@implementer(ITahoeClient)
@define
class Tahoe(object):
    """
    An object with simple bindings to Tahoe-LAFS HTTP APIs for some
    operations.

    Application code using this API lends itself well to being tested against
    the objects returned by ``MemoryGrid.client``.
    """

    client: HTTPClient
    _node_config: Config

    @property
    def _api_root(self) -> DecodedURL:
        # The reading of node.url is intentionally delayed until it is
        # required for the benefit of test code that doesn't ever make any
        # requests and also doesn't fully populate the node's filesystem
        # state.
        return read_node_url(self._node_config)

    def get_config(self) -> TahoeConfig:
        """
        Create an abstract configuration from this node's concrete configuration.
        """
        return TahoeConfig(
            ShareEncoding(
                get_configured_shares_needed(self._node_config),
                get_configured_shares_total(self._node_config),
            )
        )

    def get_private_path(self, name: str) -> FilePath:
        """
        Get the path to a file in the node's private directory.
        """
        return FilePath(self._node_config.get_private_path(name))  # type: ignore[no-untyped-call]

    async def download(self, outpath: FilePath, cap: ReadCapability) -> None:
        await download(self.client, outpath, self._api_root, cap)

    async def upload(self, get_data_provider: DataProvider) -> ReadCapability:
        return await upload_bytes(self.client, get_data_provider, self._api_root)

    async def make_directory(self) -> str:
        return await make_directory(self.client, self._api_root)

    async def list_directory(self, dir_cap: str) -> _DirectoryListing:
        return await list_directory(self.client, self._api_root, dir_cap)

    async def link(self, dir_cap: str, entry_name: str, entry_cap: str) -> None:
        return await link(self.client, self._api_root, dir_cap, entry_name, entry_cap)

    async def unlink(self, dir_cap: str, entry_name: str) -> None:
        return await unlink(self.client, self._api_root, dir_cap, entry_name)


@define
class _MemoryDirectory:
    """
    Represent a Tahoe-LAFS directory object.

    :ivar children: A mapping from an entry name to a capability which can be
        used to look up the object for that entry.
    """

    children: dict[str, CapStr] = Factory(dict)


@define
class MemoryGrid:
    """
    An extremely simplified in-memory model of a Tahoe-LAFS storage grid.
    This object allows data to be "uploaded" to it and produces capability
    strings which can then be used to "download" the data from it later on.

    :ivar _counter: An internal counter used to support the creation of
        capability strings.

    :ivar _objects: Storage for all data which has been "uploaded", as a
        mapping from the capability strings to the values.
    """

    _counter: int = 0
    _objects: dict[CapStr, Union[bytes, _MemoryDirectory]] = field(
        default=Factory(dict)
    )

    def client(
        self,
        basedir: Optional[FilePath] = None,
        share_encoding: ShareEncoding = ShareEncoding(3, 10),
    ) -> ITahoeClient:
        """
        Create a ``Tahoe``-alike that is backed by this object instead of by a
        real Tahoe-LAFS storage grid.
        """
        if basedir is None:
            basedir = FilePath(mkdtemp(suffix=".memory-tahoe"))  # type: ignore[no-untyped-call]
        return _MemoryTahoe(self, basedir, share_encoding)

    def upload(self, data: bytes) -> ReadCapability:
        assert isinstance(data, bytes)

        def encode(n: int, w: int) -> bytes:
            return n.to_bytes(w, "big")

        cap = CHKRead(
            readkey=encode(self._counter, 16),
            verifier=CHKVerify(
                storage_index=encode(self._counter, 16),
                uri_extension_hash=encode(self._counter, 32),
                needed=self._counter % 256,
                total=self._counter % 256,
                size=self._counter,
            ),
        )
        cap_str = danger_real_capability_string(cap)
        self._objects[cap_str] = data
        self._counter += 1
        return cap

    def download(self, cap: ReadCapability) -> bytes:
        data = self._objects[danger_real_capability_string(cap)]
        assert isinstance(data, bytes)
        return data

    def make_directory(self) -> CapStr:
        def encode(n: int, w: int) -> bytes:
            return n.to_bytes(w, "big")

        writekey = encode(self._counter, 16)
        fingerprint = encode(self._counter, 32)

        self._counter += 1
        cap = SSKDirectoryWrite(
            cap_object=SSKWrite.derive(writekey, fingerprint),
        )
        rw_cap_str = danger_real_capability_string(cap)
        ro_cap_str = danger_real_capability_string(cap.reader)
        dirobj = _MemoryDirectory()
        for cap_str in [rw_cap_str, ro_cap_str]:
            self._objects[cap_str] = dirobj

        return rw_cap_str

    def link(self, dir_cap: CapStr, entry_name: str, entry_cap: CapStr) -> None:
        capobj = capability_from_string(dir_cap)
        if not is_write(capobj):
            raise NotWriteableError()
        if not is_directory(capobj):
            raise ValueError(
                f"Cannot link entry into non-directory capability ({dir_cap[:7]})"
            )
        else:
            dirobj = self._objects[dir_cap]
            # It is a directory cap so we know the object will be a
            # _MemoryDirectory.
            assert isinstance(dirobj, _MemoryDirectory)
            dirobj.children[entry_name] = entry_cap

    def unlink(self, dir_cap: CapStr, entry_name: str) -> None:
        capobj = capability_from_string(dir_cap)
        if not is_write(capobj):
            raise NotWriteableError()
        if not is_directory(capobj):
            raise NotADirectoryError()
        dirobj = self._objects[dir_cap]
        # It is a directory cap so we know the object will be a _MemoryDirectory.
        assert isinstance(dirobj, _MemoryDirectory)
        del dirobj.children[entry_name]

    def list_directory(self, dir_cap: CapStr) -> _DirectoryListing:
        def describe(cap_str: CapStr) -> _DirectoryEntry:
            dir_cap_ro: DirectoryReadCapability
            cap_ro: ReadCapability

            obj = self._objects[cap_str]
            try:
                try:
                    dir_cap_rw = writeable_directory_from_string(cap_str)
                    dir_cap_ro = dir_cap_rw.reader
                except NotRecognized:
                    dir_cap_ro = readonly_directory_from_string(cap_str)
                return DirectoryNode(dir_cap_ro)
            except NotRecognized:
                pass

            try:
                cap_rw = writeable_from_string(cap_str)
                cap_ro = cap_rw.reader
            except NotRecognized:
                cap_ro = readable_from_string(cap_str)
            assert isinstance(obj, bytes), f"{obj!r}"
            return FileNode(len(obj), cap_ro)

        dirobj = self._objects[dir_cap]
        if isinstance(dirobj, _MemoryDirectory):
            return {name: describe(entry) for (name, entry) in dirobj.children.items()}

        raise ValueError(f"Cannot list a non-directory capability ({dir_cap[:7]})")


_no_children_message = (
    "\n<html>\n"
    "  <head><title>400 - Files have no children named 'somepath'</title></head>\n"
    "  <body>\n"
    "    <h1>Files have no children named {path!r}'</h1>\n"
    "    <p>no details</p>\n"
    "  </body>\n"
    "</html>\n"
)


@implementer(ITahoeClient)
@define
class _MemoryTahoe:
    """
    An in-memory implementation of the ``Tahoe`` API.
    """

    _grid: MemoryGrid
    _nodedir: FilePath
    share_encoding: ShareEncoding

    def __attrs_post_init__(self) -> None:
        self._nodedir.child("private").makedirs(ignoreExistingDirectory=True)  # type: ignore[no-untyped-call]

    def get_config(self) -> TahoeConfig:
        """
        Get this node's configuration.
        """
        return TahoeConfig(self.share_encoding)

    def get_private_path(self, name: str) -> FilePath:
        """
        Get the path to a file in a private directory dedicated to this instance
        (there is no Tahoe node directory to look in).
        """
        return cast(FilePath, self._nodedir.child("private").child(name))  # type: ignore[no-untyped-call]

    async def download(self, outpath: FilePath, cap: ReadCapability) -> None:
        data = self._grid.download(cap)
        assert isinstance(data, bytes)
        outpath.setContent(data)  # type: ignore[no-untyped-call]

    async def upload(self, data_provider: DataProvider) -> ReadCapability:
        """
        Send some data to Tahoe-LAFS, returning an immutable capability.

        :param get_data: a function that returns the data to
            upload. This may be called more than once in case we need
            to re-try the upload, which is also the reason this method
            doesn't just take a `bytes` directly
        """
        with data_provider() as d:
            content = d.read()
        return self._grid.upload(content)

    async def make_directory(self) -> CapStr:
        return self._grid.make_directory()

    async def link(self, dir_cap: CapStr, entry_name: str, entry_cap: CapStr) -> None:
        return self._grid.link(dir_cap, entry_name, entry_cap)

    async def unlink(self, dir_cap: CapStr, entry_name: str) -> None:
        return self._grid.unlink(dir_cap, entry_name)

    async def list_directory(self, dir_cap: CapStr) -> _DirectoryListing:
        return self._grid.list_directory(dir_cap)


async def download_child(
    outpath: FilePath,
    client: ITahoeClient,
    dircap: DirectoryReadCapability,
    child_path: List[str],
) -> None:
    """
    Download a child from the identified directory.

    :param outpath: The local filesystem path to which to write the downloaded
        data.

    :param client: The client to use for the download.

    :param dircap: The capability of the containing directory.

    :param, child_path: The child names to use to find the data to download.
        Each element in the list is the name of an entry in a directory.  The
        first element is an entry in ``dircap``, the next element is an entry
        in whatever directory the first identified, and so on.  The final
        element must identify a regular file and all other elements must
        identify directories.

    :return: ``None`` after the download is complete.
    """
    if len(child_path) == 0:
        raise ValueError("Path to child must be provided")
    else:
        p = child_path[0]
        remaining_path = child_path[1:]
        children = await client.list_directory(danger_real_capability_string(dircap))
        child = children[p]

        if remaining_path:
            if isinstance(child, DirectoryNode):
                await download_child(outpath, client, child.ro_uri, remaining_path)
            else:
                raise NotADirectoryError(digested_capability_string(child.ro_uri))
        else:
            assert isinstance(child, FileNode)
            await client.download(outpath, child.ro_uri)


def attenuate_writecap(rw_cap: CapStr) -> CapStr:
    """
    Get a read-only capability corresponding to the same data as the given
    read-write capability.
    """

    return danger_real_capability_string(writeable_from_string(rw_cap).reader)


def get_tahoe_client(reactor: IReactorTCP, node_config: Config) -> ITahoeClient:
    """
    Return a Tahoe-LAFS client appropriate for the given node configuration.

    :param reactor: The reactor the client will use for I/O.

    :param node_config: The Tahoe-LAFS client node configuration for the
        client (giving, for example, the root URI of the node's HTTP API).
    """
    agent = Agent(reactor)  # type: ignore[no-untyped-call]
    http_client = HTTPClient(agent)
    return Tahoe(http_client, node_config)


def required_passes_for_data(
    bytes_per_pass: int, encoding: ShareEncoding, data_size: int
) -> int:
    """
    Calculate the total storage cost (in passes) for all shares of an object
    of a certain size under certain encoding parameters and pass value.
    """
    return required_passes(
        bytes_per_pass,
        share_sizes_for_data(encoding, data_size),
    )


def share_sizes_for_data(encoding: ShareEncoding, data_size: int) -> list[int]:
    """
    Get the sizes of all of the shares for data of the given size encoded
    using the given encoding.
    """
    return [share_size_for_data(encoding.needed, data_size)] * encoding.total
