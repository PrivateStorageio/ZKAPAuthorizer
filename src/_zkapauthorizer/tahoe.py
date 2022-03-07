"""
A library for interacting with a Tahoe-LAFS node.
"""

from collections.abc import Awaitable
from functools import wraps
from hashlib import sha256
from tempfile import mkdtemp
from typing import Callable, Dict, Iterable, List, Optional

import treq
from allmydata.node import _Config
from allmydata.uri import from_string as capability_from_string
from allmydata.util.base32 import b2a as b32encode
from attrs import Factory, define, field
from hyperlink import DecodedURL
from treq.client import HTTPClient
from twisted.python.filepath import FilePath

from .config import read_node_url


def async_retry(matchers: List[Callable[[Exception], bool]]):
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


@define(frozen=True, auto_exc=False)
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


@async_retry([_not_enough_servers])
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
    uri = api_root.child("uri")
    with inpath.open() as f:
        resp = await client.put(uri, f)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code in (200, 201):
        return content
    raise TahoeAPIError("put", uri, resp.code, content)


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


@async_retry([_not_enough_servers])
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


@async_retry([_not_enough_servers])
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

    def make_directory(self):
        return make_directory(self.client, self._api_root)


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
    _objects: Dict[str, str] = field(default=Factory(dict))

    def client(self):
        """
        Create a ``Tahoe``-alike that is backed by this object instead of by a
        real Tahoe-LAFS storage grid.
        """
        return _MemoryTahoe(self)

    def upload(self, data: bytes) -> str:
        cap = str(self._counter)
        self._objects[cap] = data
        self._counter += 1
        return cap

    def download(self, cap: str) -> bytes:
        return self._objects[cap]

    def make_directory(self) -> str:
        def encode(s: bytes):
            return b32encode(s.encode("ascii")).decode("ascii")

        writekey = encode("{:016x}".format(self._counter))
        fingerprint = encode("{:032x}".format(self._counter))

        self._counter += 1
        cap = f"URI:DIR2:{writekey}:{fingerprint}"
        rocap = capability_from_string(cap).get_readonly().to_string().decode("ascii")
        self._objects[cap] = self._objects[rocap] = {}

        return cap


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
        assert len(child_path) == 0
        outpath.setContent(self._grid.download(cap))

    async def upload(self, inpath):
        return self._grid.upload(inpath.getContent())

    async def make_directory(self):
        return self._grid.make_directory()


def attenuate_writecap(rw_cap: str) -> str:
    """
    Get a read-only capability corresponding to the same data as the given
    read-write capability.
    """
    return capability_from_string(rw_cap).get_readonly().to_string().decode("ascii")
