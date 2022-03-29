"""
A library for interacting with a Tahoe-LAFS node.
"""

from collections.abc import Awaitable
from functools import wraps
from hashlib import sha256
from io import BytesIO
from json import loads
from tempfile import mkdtemp
from typing import Callable, Iterable, Optional, Union, BinaryIO

import treq
from allmydata.node import _Config
from allmydata.uri import from_string as capability_from_string
from allmydata.util.base32 import b2a as b32encode
from attrs import Factory, define, field
from hyperlink import DecodedURL
from treq.client import HTTPClient
from twisted.internet.error import ConnectionRefusedError
from twisted.python.filepath import FilePath
from twisted.web.client import Agent

from ._json import dumps_utf8
from .config import read_node_url


def async_retry(matchers: list[Callable[[Exception], bool]]):
    """
    Decorate a function with automatic retry behavior for certain cases.

    :param matchers: A list of objects with a ``match`` method.  If any of
        these return ``True`` for an exception raised by the decorated
        function then the decorated function will be called again.
    """

    def retry_decorator(f) -> Callable:
        @wraps(f)
        async def decorated(*a, **kw) -> Awaitable:
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


def _not_enough_servers(exc: Exception) -> bool:
    """
    Match the exception that is raised when the Tahoe-LAFS client node is not
    connected to enough servers to satisfy the encoding configuration.
    """
    return isinstance(exc, TahoeAPIError) and (
        "allmydata.interfaces.NoServersError" in str(exc)
        or "allmydata.mutable.common.NotEnoughServersError" in str(exc)
    )


def _connection_refused(exc: Exception) -> bool:
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
        new = url.replace(path=(url.path[0], _scrub_cap(cap)) + url.path[2:])
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


_common_tahoe_errors = [_not_enough_servers, _connection_refused]


@async_retry(_common_tahoe_errors)
async def upload_bytes(
    client: HTTPClient,
    data: BinaryIO,
    api_root: DecodedURL,
) -> Awaitable[str]:
    """
    Upload the given data and return the resulting capability.

    If not enough storage servers are reachable then the upload is
    automatically retried.

    :param client: An HTTP client to use to make requests to the Tahoe-LAFS
        HTTP API to perform the upload.

    :param data: Source of bytes to upload

    :param api_root: The location of the root of the Tahoe-LAFS HTTP API to
        use to perform the upload.  This should typically be the ``node.url``
        value from a Tahoe-LAFS client node.

    :return: If the upload is successful then the capability of the uploaded
        data is returned.

    :raise: If there is a problem uploading the data -- except for
        unavailability of storage servers -- then some exception is raised.
    """
    uri = api_root.child("uri")
    resp = await client.put(uri, data)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code in (200, 201):
        return content
    raise TahoeAPIError("put", uri, resp.code, content)


@async_retry(_common_tahoe_errors)
async def upload(
    client: HTTPClient, inpath: FilePath, api_root: DecodedURL
) -> Awaitable[str]:
    """
    Upload data from the given path and return the resulting capability.

    If not enough storage servers are reachable then the upload is
    automatically retried.

    :param client: An HTTP client to use to make requests to the Tahoe-LAFS
        HTTP API to perform the upload.

    :param inpath: The path to the regular file to upload.

    :param api_root: The location of the root of the Tahoe-LAFS HTTP API to
        use to perform the upload.  This should typically be the ``node.url``
        value from a Tahoe-LAFS client node.

    :return: If the upload is successful then the capability of the uploaded
        data is returned.

    :raise: If there is a problem uploading the data -- except for
        unavailability of storage servers -- then some exception is raised.
    """
    with inpath.open() as f:
        capability = await upload_bytes(client, f, api_root)
    return capability


async def download(
    client: HTTPClient,
    outpath: FilePath,
    api_root: DecodedURL,
    cap: str,
    child_path: Optional[Iterable[str]] = None,
) -> Awaitable[None]:
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

    :raise: If there is a problem downloading the data then some exception is
        raised.
    """
    outtemp = outpath.temporarySibling()

    uri = api_root.child("uri").child(cap)
    if child_path is not None:
        for segment in child_path:
            uri = uri.child(segment)

    resp = await client.get(uri)
    if resp.code == 200:
        with outtemp.open("w") as f:
            await treq.collect(resp, f.write)
        outtemp.moveTo(outpath)
    else:
        content = (await treq.content(resp)).decode("utf-8")
        raise TahoeAPIError("get", uri, resp.code, content)


@async_retry(_common_tahoe_errors)
async def list_directory(
    client: HTTPClient,
    api_root: DecodedURL,
    dir_cap: str,
) -> Awaitable[dict[str, dict[str, dict]]]:
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
        return details["children"]

    raise TahoeAPIError("get", uri, resp.code, content)


@async_retry(_common_tahoe_errors)
async def make_directory(
    client: HTTPClient,
    api_root: DecodedURL,
) -> Awaitable[str]:
    """
    Create a new mutable directory and return the write capability string.
    """
    uri = api_root.child("uri").add("t", "mkdir")
    resp = await client.post(uri)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code == 200:
        return content
    raise TahoeAPIError("post", uri, resp.code, content)


@async_retry(_common_tahoe_errors)
async def link(
    client: HTTPClient,
    api_root: DecodedURL,
    dir_cap: str,
    entry_name: str,
    entry_cap: str,
) -> Awaitable[None]:
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


@define
class Tahoe(object):
    """
    An object with simple bindings to Tahoe-LAFS HTTP APIs for some
    operations.

    Application code using this API lends itself well to being tested against
    the objects returned by ``MemoryGrid.client``.
    """

    client: HTTPClient
    _node_config: _Config

    @property
    def _api_root(self):
        # The reading of node.url is intentionally delayed until it is
        # required for the benefit of test code that doesn't ever make any
        # requests and also doesn't fully populate the node's filesystem
        # state.
        return read_node_url(self._node_config)

    def get_private_path(self, name: str) -> FilePath:
        """
        Get the path to a file in the node's private directory.
        """
        return FilePath(self._node_config.get_private_path(name))

    def download(self, outpath, cap, child_path):
        return download(self.client, outpath, self._api_root, cap, child_path)

    def upload(self, inpath):
        return upload(self.client, inpath, self._api_root)

    def upload_bytes(self, data):
        return upload_bytes(self.client, data, self._api_root)

    def make_directory(self):
        return make_directory(self.client, self._api_root)

    def list_directory(self, dir_cap):
        return list_directory(self.client, self._api_root, dir_cap)

    def link(self, dir_cap, entry_name, entry_cap):
        return link(self.client, self._api_root, dir_cap, entry_name, entry_cap)


CapStr = str
FSEntry = Union[CapStr, dict[CapStr, "FSEntry"]]


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
    _objects: dict[CapStr, FSEntry] = field(default=Factory(dict))

    def client(self):
        """
        Create a ``Tahoe``-alike that is backed by this object instead of by a
        real Tahoe-LAFS storage grid.
        """
        return _MemoryTahoe(self)

    def upload(self, data: bytes) -> CapStr:
        cap = str(self._counter)
        self._objects[cap] = data
        self._counter += 1
        return cap

    def download(self, cap: CapStr) -> bytes:
        return self._objects[cap]

    def make_directory(self) -> CapStr:
        def encode(s: bytes):
            return b32encode(s.encode("ascii")).decode("ascii")

        writekey = encode("{:016x}".format(self._counter))
        fingerprint = encode("{:032x}".format(self._counter))

        self._counter += 1
        cap = f"URI:DIR2:{writekey}:{fingerprint}"
        rocap = attenuate_writecap(cap)
        self._objects[cap] = self._objects[rocap] = {}

        return cap

    def link(self, dir_cap: CapStr, entry_name: str, entry_cap: CapStr) -> None:
        d = capability_from_string(dir_cap)
        if d.is_readonly():
            raise NotWriteableError()
        self._objects[dir_cap][entry_name] = entry_cap

    def list_directory(self, dir_cap: CapStr) -> dict[CapStr, FSEntry]:
        def kind(entry):
            if isinstance(entry, dict):
                return "dirnode"
            return "filenode"

        def describe(cap):
            obj = self._objects[cap]
            if kind(obj) == "dirnode":
                return ["dirnode", {"rw_uri": cap}]
            return ["filenode", {"size": len(obj)}]

        dir_entries = self._objects[dir_cap]
        if kind(dir_entries) == "dirnode":
            return {name: describe(entry) for (name, entry) in dir_entries.items()}

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


@define
class _MemoryTahoe:
    """
    An in-memory implementation of the ``Tahoe`` API.
    """

    _grid: MemoryGrid
    _nodedir: FilePath = field()

    @_nodedir.default
    def _nodedir_default(self):
        return FilePath(mkdtemp(suffix=".memory-tahoe"))

    def __attrs_post_init__(self):
        self._nodedir.child("private").makedirs()

    def get_private_path(self, name: str) -> FilePath:
        """
        Get the path to a file in a private directory dedicated to this instance
        (there is no Tahoe node directory to look in).
        """
        return self._nodedir.child("private").child(name)

    async def download(self, outpath, cap, child_path):
        d = self._grid.download(cap)
        if child_path is not None:
            for p in child_path:
                if cap.startswith("URI:DIR2"):
                    cap = d[p]
                    d = self._grid.download(cap)
                else:
                    raise TahoeAPIError(
                        "get", DecodedURL(), 400, _no_children_message.format(path=p)
                    )
        if isinstance(d, dict):
            # It is a directory.  Encode it somehow so it fits in the file.
            # This is not the same encoding as Tahoe-LAFS itself uses for
            # directories.
            d = dumps_utf8(d)
        outpath.setContent(d)

    async def upload(self, inpath):
        return self._grid.upload(inpath.getContent())

    async def make_directory(self):
        return self._grid.make_directory()

    async def link(self, dir_cap, entry_name, entry_cap):
        return self._grid.link(dir_cap, entry_name, entry_cap)

    async def list_directory(self, dir_cap):
        return self._grid.list_directory(dir_cap)


def attenuate_writecap(rw_cap: CapStr) -> CapStr:
    """
    Get a read-only capability corresponding to the same data as the given
    read-write capability.
    """
    return capability_from_string(rw_cap).get_readonly().to_string().decode("ascii")


def get_tahoe_client(reactor, node_config: _Config) -> Tahoe:
    """
    Return a Tahoe-LAFS client appropriate for the given node configuration.

    :param reactor: The reactor the client will use for I/O.

    :param node_config: The Tahoe-LAFS client node configuration for the
        client (giving, for example, the root URI of the node's HTTP API).
    """
    agent = Agent(reactor)
    http_client = HTTPClient(agent)
    return Tahoe(http_client, node_config)
