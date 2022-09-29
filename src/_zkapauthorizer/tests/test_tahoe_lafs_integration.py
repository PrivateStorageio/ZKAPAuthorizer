"""
Tests for ``_zkapauthorizer._plugin.storage_server_plugin`` / Tahoe-LAFS
integration.
"""

from io import BytesIO

from fixtures import TempDir
from testresources import (
    OptimisingTestSuite,
    TestLoader,
    _get_result,
    setUpResources,
    tearDownResources,
)
from testtools import TestCase
from testtools.matchers import FileContains
from testtools.twistedsupport import AsynchronousDeferredRunTest
from twisted.internet.defer import Deferred
from twisted.python.filepath import FilePath

from .. import NAME
from .._json import dumps_utf8
from ..tahoe import get_tahoe_client
from .resources import ZKAPTahoeGrid


class IntegrationTests(TestCase):
    """
    Test ZKAPAuthorizer functionality through the Tahoe-LAFS web API.

    We use ITahoeClient to asynchronously interact with the Tahoe-LAFS client
    node so we ask testtools to run our tests in a way that supports
    asynchronous, Deferred- or coroutine-returning test methods.

    Hypothesis interacts poorly with asynchronous tests so we hard-code some
    sample values instead.
    """

    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=10.0)

    resources = [("grid", ZKAPTahoeGrid())]

    def setUp(self) -> None:
        super().setUp()
        self.setUpResources()

        from twisted.internet import reactor
        from twisted.internet.interfaces import IReactorTCP

        assert IReactorTCP.providedBy(reactor)

        self.reactor = reactor
        self.client = get_tahoe_client(reactor, self.grid.client.read_config())

        def f() -> Deferred[None]:
            # Let the reactor turn over to complete the HTTP11Connection
            # disconnection. https://github.com/twisted/twisted/issues/8998
            from twisted.internet.task import deferLater

            return deferLater(self.reactor, 0.0, lambda: None)

        self.addCleanup(f)

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
        token = (
            self.client.get_private_path("api_auth_token").getContent().decode("ascii")
        )
        headers = {"authorization": f"tahoe-lafs {token}"}

        from treq.client import HTTPClient
        from twisted.web.client import Agent

        agent = Agent(self.reactor)
        http_client = HTTPClient(agent)

        api_root = self.grid.client.node_url
        assert api_root is not None
        await http_client.put(
            api_root.child("storage-plugins").child(NAME).child("voucher"),
            headers=headers,
            data=dumps_utf8({"voucher": "x" * 44}),
        )

        from testtools.content import content_from_file

        # XXX Replace content_from_file with something that renders eliot logs w/ eliot-tree
        self.addDetail(
            "client-eliot-log",
            content_from_file(self.grid.client.node_dir.child("log.eliot").path),
        )
        self.addDetail(
            "client-stdout",
            content_from_file(self.grid.client.node_dir.child("stdout").path),
        )
        self.addDetail(
            "client-stderr",
            content_from_file(self.grid.client.node_dir.child("stderr").path),
        )

        self.addDetail(
            "storage-eliot-log",
            content_from_file(self.grid.storage.node_dir.child("log.eliot").path),
        )
        self.addDetail(
            "storage-stdout",
            content_from_file(self.grid.storage.node_dir.child("stdout").path),
        )
        self.addDetail(
            "storage-stderr",
            content_from_file(self.grid.storage.node_dir.child("stderr").path),
        )

        tempdir = self.useFixture(TempDir())
        outpath = FilePath(tempdir.join("downloaded"))

        expected = "Some test bytes" * 16
        ro_cap = await self.client.upload(lambda: BytesIO(expected.encode("ascii")))
        await self.client.download(outpath, ro_cap)

        self.assertThat(outpath.path, FileContains(expected))


def testSuite() -> OptimisingTestSuite:
    return OptimisingTestSuite(TestLoader().loadTestsFromTestCase(IntegrationTests))
