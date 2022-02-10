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
) -> Awaitable[str]:
    """
    Upload data from the given path and return the resulting capability.
    """
    with inpath.open() as f:
        resp = await client.put(api_root.child("uri"), f)
    content = (await treq.content(resp)).decode("utf-8")
    if resp.code in (200, 201):
        return content
    raise Exception(content)


async def download(
    client: HTTPClient, outpath: FilePath, api_root: DecodedURL, cap: str
) -> Awaitable[None]:
    """
    Download the object identified by the given capability to the given path.
    """
    outtemp = outpath.temporarySibling()

    resp = await client.get(api_root.child("uri", cap).to_text())
    if resp.code == 200:
        with outtemp.open("w") as f:
            await treq.collect(resp, f.write)
        outtemp.moveTo(outpath)
    else:
        content = await treq.content(resp)
        raise Exception(content.decode("utf-8"))
