"""
Tests for ``_zkapauthorizer._plugin.storage_server_plugin`` / Tahoe-LAFS
integration.
"""

from io import BytesIO
from typing import TYPE_CHECKING

from fixtures import TempDir
from hyperlink import DecodedURL
from testresources import (
    OptimisingTestSuite,
    TestLoader,
    _get_result,
    setUpResources,
    tearDownResources,
)
from testtools import TestCase
from testtools.matchers import Equals, FileContains
from testtools.twistedsupport import AsynchronousDeferredRunTest
from treq.client import HTTPClient
from twisted.internet.interfaces import IReactorTCP, IReactorTime
from twisted.internet.task import deferLater
from twisted.python.filepath import FilePath
from twisted.web.client import Agent

from .. import NAME
from .._json import dumps_utf8
from ..tahoe import get_tahoe_client
from .resources import ZKAPTahoeGrid

if TYPE_CHECKING:

    class IReactorTCPTime(IReactorTCP, IReactorTime):
        """
        From Mypy's perspective, both ``IReactorTCP`` and ``IReactorTime``.

        Unfortunately, from zope.interface's perspective, nothing implements
        this interface.  Thus, it is only defined at type checking time so you
        cannot accidentally use it to make bogus runtime checks.
        """


async def addZKAPs(
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

    async def addZKAPs(self) -> None:
        # Load up the client with some ZKAPs
        api_root = self.grid.client.node_url
        assert api_root is not None
        await addZKAPs(self.http_client, api_root, self.grid.client.authorization)

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
        await self.addZKAPs()

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
        await self.addZKAPs()

        rw_cap = await self.client.make_directory()
        children = await self.client.list_directory(rw_cap.reader)
        self.assertThat(children, Equals({}))


def testSuite() -> OptimisingTestSuite:
    return OptimisingTestSuite(TestLoader().loadTestsFromTestCase(IntegrationTests))
