"""
Tests for ``_zkapauthorizer._plugin.storage_server_plugin`` / Tahoe-LAFS
integration.
"""

from base64 import b32encode
from io import BytesIO
from json import dumps
from typing import TYPE_CHECKING

from fixtures import TempDir
from hyperlink import DecodedURL
from tahoe_capabilities import LiteralRead, danger_real_capability_string
from testresources import (
    OptimisingTestSuite,
    TestLoader,
    _get_result,
    setUpResources,
    tearDownResources,
)
from testtools import TestCase
from testtools.content import text_content
from testtools.matchers import Contains, Equals, FileContains, Not
from testtools.twistedsupport import AsynchronousDeferredRunTest
from treq.client import HTTPClient
from twisted.internet.interfaces import IReactorTCP, IReactorTime
from twisted.internet.task import deferLater
from twisted.python.filepath import FilePath
from twisted.web.client import Agent

from .. import NAME
from .._json import dumps_utf8
from ..tahoe import TahoeAPIError, get_tahoe_client
from .resources import ZKAPTahoeGrid

if TYPE_CHECKING:

    class IReactorTCPTime(IReactorTCP, IReactorTime):
        """
        From Mypy's perspective, both ``IReactorTCP`` and ``IReactorTime``.

        Unfortunately, from zope.interface's perspective, nothing implements
        this interface.  Thus, it is only defined at type checking time so you
        cannot accidentally use it to make bogus runtime checks.
        """


async def add_zkaps(
    http_client: HTTPClient, api_root: DecodedURL, authorization: dict[str, str]
) -> None:
    await http_client.put(
        api_root.child("storage-plugins").child(NAME).child("voucher"),
        headers=authorization,
        data=dumps_utf8({"voucher": "x" * 44}),
    )


class IntegrationTests(TestCase):
    """
    Test ZKAPAuthorizer functionality through the Tahoe-LAFS web API.

    We use ITahoeClient to asynchronously interact with the Tahoe-LAFS client
    node so we ask testtools to run our tests in a way that supports
    asynchronous, Deferred- or coroutine-returning test methods.

    Hypothesis interacts poorly with asynchronous tests so we hard-code some
    sample values instead.
    """

    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=1000.0)

    resources = [
        ("grid", ZKAPTahoeGrid()),
    ]

    def setUp(self) -> None:
        super().setUp()

        from twisted.internet import reactor

        self.reactor: "IReactorTCPTime" = reactor  # type: ignore[assignment]
        self.setUpResources()
        self.grid.addDetail(self)

        self.client = get_tahoe_client(self.reactor, self.grid.client.read_config())
        self.agent = Agent(self.reactor)
        self.http_client = HTTPClient(self.agent)

        # Let the reactor turn over to complete the HTTP11Connection
        # disconnection.  https://github.com/twisted/twisted/issues/8998
        self.addCleanup(lambda: deferLater(self.reactor, 0.0, lambda: None))

    async def add_zkaps(self) -> None:
        # Load up the client with some ZKAPs
        api_root = self.grid.client.node_url
        assert api_root is not None
        await add_zkaps(self.http_client, api_root, self.grid.client.authorization)

    def setUpResources(self) -> None:
        setUpResources(self, self.resources, _get_result())

    def tearDown(self) -> None:
        self.tearDownResources()
        super().tearDown()

    def tearDownResources(self) -> None:
        tearDownResources(self, self.resources, _get_result())

    async def test_uploadDownloadImmutable(self) -> None:
        """
        A new immutable object can be uploaded and downloaded again.
        """
        await self.add_zkaps()

        tempdir = self.useFixture(TempDir())
        outpath = FilePath(tempdir.join("downloaded"))

        expected = "Some test bytes" * (2**10)
        ro_cap = await self.client.upload(lambda: BytesIO(expected.encode("ascii")))
        await self.client.download(outpath, ro_cap)

        self.assertThat(outpath.path, FileContains(expected))

    async def test_uploadDownloadMutable(self) -> None:
        """
        A new mutable object can be uploaded and downloaded again.
        """
        await self.add_zkaps()

        rw_cap = await self.client.make_directory()
        children = await self.client.list_directory(rw_cap.reader)
        self.assertThat(children, Equals({}))

    async def test_renewLease(self) -> None:
        """
        An existing share can have its lease renewed.
        """
        await self.add_zkaps()

        expected = "xyz" * 1024
        ro_cap = await self.client.upload(lambda: BytesIO(expected.encode("ascii")))

        # If it's a literal cap then leases aren't applicable.
        assert not isinstance(ro_cap, LiteralRead)

        # Scrounge!
        share_path = self.grid.client.storage.get_share_path(ro_cap.verifier, 0)
        share_before = share_path.getContent()

        # Leases have a resolution of one second so if we don't let the
        # wallclock seconds counter tick over to a new value we won't be able
        # to observe the lease renewal!
        await deferLater(self.reactor, 1.0, lambda: None)

        api_root = self.grid.client.node_url
        add_lease = (
            api_root.child("uri", danger_real_capability_string(ro_cap))
            .add("t", "check")
            .add("add-lease", "true")
            .add("output", "JSON")
        )
        response = await self.http_client.post(add_lease)
        content = await response.json()

        self.addDetail("check-output", text_content(dumps(content)))
        self.assertThat(response.code, Equals(200))
        self.assertThat(content["summary"], Equals("Healthy"))

        share_after = share_path.getContent()

        # check succeeds whether a lease is added or not so we should also
        # verify that the lease was really added.
        self.assertThat(share_before, Not(Equals(share_after)))

    async def test_advise_corrupt_share(self) -> None:
        """
        A corruption advisory is reported to the storage server when the
        storage client decides a share is corrupt.
        """
        await self.add_zkaps()

        expected = "xyz" * 1024
        ro_cap = await self.client.upload(lambda: BytesIO(expected.encode("ascii")))

        # If it's a literal cap then corruption advisories aren't applicable.
        assert not isinstance(ro_cap, LiteralRead)

        # Mess it up.
        share_path = self.grid.client.storage.get_share_path(ro_cap.verifier, 0)

        # Try to find a ciphertext block and scribble over some of it.
        with share_path.open("r+") as f:
            f.seek(200)
            f.write(b"x")

        # Try to download it - we can't because it's broken.
        tempdir = self.useFixture(TempDir())
        outpath = FilePath(tempdir.join("downloaded"))

        try:
            await self.client.download(outpath, ro_cap)
        except TahoeAPIError:
            pass
        else:
            self.addDetail(
                "downloaded-object", text_content(outpath.getContent().decode("ascii"))
            )
            self.fail("expected download of corrupt share to fail")

        # Check for the corruption advisory.
        advisories = self.grid.client.storage.get_corruption_advisories().children()
        self.assertThat(advisories, Not(Equals([])))
        self.assertThat(
            advisories[0].path,
            FileContains(
                matcher=Contains(
                    f"storage_index: {b32encode(ro_cap.verifier.storage_index).strip(b'=').lower().decode('ascii')}"
                )
            ),
        )


def testSuite() -> OptimisingTestSuite:
    return OptimisingTestSuite(TestLoader().loadTestsFromTestCase(IntegrationTests))
