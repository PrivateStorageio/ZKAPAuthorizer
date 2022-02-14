"""
A library for interacting with a Tahoe-LAFS node.
"""

from collections.abc import Awaitable

import treq
from hyperlink import DecodedURL
from treq.client import HTTPClient
from twisted.python.filepath import FilePath


async def upload(
    client: HTTPClient, inpath: FilePath, api_root: DecodedURL
) -> Awaitable:  # Awaitable[str] but this requires Python 3.9
    """
    Upload data from the given path and return the resulting capability.

    :param client: An HTTP client to use to make requests to the Tahoe-LAFS
        HTTP API to perform the upload.

    :param inpath: The path to the regular file to upload.

    :param api_root: The location of the root of the Tahoe-LAFS HTTP API to
        use to perform the upload.  This should typically be the ``node.url``
        value from a Tahoe-LAFS client node.

    :return: If the upload is successful then the capability of the uploaded
        data is returned.

    :raise: If there is a problem uploading the data, some exception is
        raised.
    """
    with inpath.open() as f:
        resp = await client.put(api_root.child("uri"), f)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code in (200, 201):
        return content
    raise Exception(content)


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

    :raise: If there is a problem downloading the data, some exception is
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
        raise Exception(content)
