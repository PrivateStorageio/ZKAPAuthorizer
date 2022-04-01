"""
Tests for ``_zkapauthorizer.recover``, the replication recovery system.
"""

from datetime import datetime

from allmydata.client import read_config
from testresources import setUpResources, tearDownResources
from testtools import TestCase
from testtools.matchers import AfterPreprocessing, Equals
from testtools.twistedsupport import AsynchronousDeferredRunTest
from twisted.internet.defer import Deferred, inlineCallbacks

from ..replicate import event_stream_observer
from ..tahoe import Tahoe, make_directory
from .fixtures import ConfiglessMemoryVoucherStore, Treq
from .resources import client_manager


class ObserverTests(TestCase):
    """
    Test the event-stream observer
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    # Get a Tahoe-LAFS client node connected to a storage node.
    resources = [("client", client_manager)]

    def setUp(self):
        super().setUp()
        setUpResources(self, self.resources, None)
        self.addCleanup(lambda: tearDownResources(self, self.resources, None))

    @inlineCallbacks
    def test_observer(self):
        """
        Various kinds of SQL statements can be serialized into and out of
        the event-stream.
        """
        config = read_config(self.client.node_dir.path, "tub.port")
        httpclient = self.useFixture(Treq(self.reactor, case=self)).client()
        tahoeclient = Tahoe(httpclient, config)

        store = self.useFixture(
            ConfiglessMemoryVoucherStore(
                # Time is not relevant to this test
                datetime.now,
            )
        ).store

        replica_dir_cap_str = yield Deferred.fromCoroutine(
            make_directory(httpclient, self.client.node_url),
        )

        # create 2 fake events
        store.add_event("CREATE TABLE [foo] ([a] INT)")
        store.add_event("INSERT INTO [foo] VALUES (1)")
        events = store.get_events()

        # let our observer see the events
        observer = event_stream_observer(
            replica_dir_cap_str, tahoeclient, store._connection
        )
        yield Deferred.fromCoroutine(observer(events))

        entries = yield Deferred.fromCoroutine(
            tahoeclient.list_directory(replica_dir_cap_str)
        )

        self.assertThat(
            entries,
            AfterPreprocessing(
                lambda entities: list(entities.keys()),
                Equals(["event-stream-2"]),
            ),
        )
