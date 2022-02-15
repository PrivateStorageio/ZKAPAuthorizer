"""
A library for interacting with a Tahoe-LAFS node.
"""

from collections.abc import Awaitable
from functools import wraps
from typing import Callable, List

import treq
from attrs import define
from hyperlink import DecodedURL
from treq.client import HTTPClient
from twisted.python.filepath import FilePath


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
    return isinstance(
        exc, TahoeAPIError
    ) and "allmydata.interfaces.NoServersError" in str(exc)


@define
class TahoeAPIError(Exception):
    """
    Some error was reported from a Tahoe-LAFS HTTP API.

    :ivar status: The HTTP response status code.
    :ivar body: The HTTP response body.
    """

    status: int
    body: str


@async_retry([_not_enough_servers])
async def upload(
    client: HTTPClient, inpath: FilePath, api_root: DecodedURL
) -> Awaitable:  # Awaitable[str] but this requires Python 3.9
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
        resp = await client.put(api_root.child("uri"), f)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code in (200, 201):
        return content
    raise TahoeAPIError(resp.code, content)


async def download(
    client: HTTPClient, outpath: FilePath, api_root: DecodedURL, cap: str
) -> Awaitable:  # Awaitable[None] but this requires Python 3.9
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

    resp = await client.get(api_root.child("uri", cap).to_text())
    if resp.code == 200:
        with outtemp.open("w") as f:
            await treq.collect(resp, f.write)
        outtemp.moveTo(outpath)
    else:
        content = (await treq.content(resp)).decode("utf-8")
        raise TahoeAPIError(resp.code, content)
