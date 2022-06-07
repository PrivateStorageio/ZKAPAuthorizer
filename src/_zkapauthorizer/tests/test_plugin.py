# Copyright 2019 PrivateStorage.io, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Tests for the Tahoe-LAFS plugin.
"""

from datetime import timedelta
from functools import partial
from io import StringIO
from os import mkdir
from sqlite3 import connect

from allmydata.client import config_from_string, create_client_from_config
from allmydata.interfaces import (
    IAnnounceableStorageServer,
    IFilesystemNode,
    IFoolscapStoragePlugin,
    IStorageServer,
    RIStorageServer,
)
from autobahn.twisted.testing import (
    MemoryReactorClockResolver,
    create_memory_agent,
    create_pumper,
)
from challenge_bypass_ristretto import SigningKey
from eliot.testing import LoggedMessage, capture_logging
from fixtures import TempDir
from foolscap.broker import Broker
from foolscap.ipb import IReferenceable, IRemotelyCallable
from foolscap.referenceable import LocalReferenceable
from hyperlink import DecodedURL
from hypothesis import given, settings
from hypothesis.strategies import floats, integers, just, sampled_from, timedeltas
from prometheus_client import Gauge
from prometheus_client.parser import text_string_to_metric_families
from testtools import TestCase
from testtools.content import text_content
from testtools.matchers import (
    AfterPreprocessing,
    AllMatch,
    Always,
    AnyMatch,
    Contains,
    ContainsDict,
    Equals,
    HasLength,
    IsInstance,
    Matcher,
    MatchesAll,
    MatchesListwise,
    MatchesPredicate,
    MatchesStructure,
    Not,
    Raises,
)
from testtools.twistedsupport import succeeded
from testtools.twistedsupport._deferred import extract_result
from treq.testing import RequestTraversalAgent
from twisted.internet.address import IPv4Address
from twisted.internet.defer import Deferred
from twisted.internet.testing import MemoryReactorClock
from twisted.plugin import getPlugins
from twisted.python.filepath import FilePath
from twisted.python.runtime import platform
from twisted.test.proto_helpers import StringTransport
from twisted.web.http_headers import Headers
from twisted.web.resource import IResource

from twisted.plugins.zkapauthorizer import storage_server_plugin

from .. import NAME
from .._plugin import (
    ZKAPAuthorizer,
    _CostBasedPolicy,
    get_recovery_websocket_resource,
    get_root_nodes,
    load_signing_key,
    open_store,
)
from .._storage_client import IncorrectStorageServerReference
from ..config import CONFIG_DB_NAME
from ..controller import DummyRedeemer, IssuerConfigurationMismatch, PaymentController
from ..foolscap import RIPrivacyPassAuthorizedStorageServer
from ..lease_maintenance import SERVICE_NAME, LeaseMaintenanceConfig
from ..model import (
    NotEnoughTokens,
    StoreOpenError,
    VoucherStore,
    memory_connect,
    open_database,
)
from ..replicate import (
    _ReplicationService,
    setup_tahoe_lafs_replication,
    statements_to_snapshot,
    with_replication,
)
from ..resource import recover
from ..spending import GET_PASSES
from ..tahoe import ITahoeClient, MemoryGrid, ShareEncoding
from .common import skipIf
from .fixtures import DetectLeakedDescriptors
from .foolscap import DummyReferenceable, LocalRemote, get_anonymous_storage_server
from .matchers import Provides, matches_response, raises
from .strategies import (
    announcements,
    aware_datetimes,
    client_dummyredeemer_configurations,
    client_lease_maintenance_configurations,
    dummy_ristretto_keys,
    encoding_parameters,
    lease_cancel_secrets,
    lease_maintenance_configurations,
    lease_renew_secrets,
    minimal_tahoe_configs,
    pass_counts,
    posix_timestamps,
    ristretto_signing_keys,
    server_configurations,
    sharenum_sets,
    sizes,
    storage_indexes,
    tahoe_configs,
    vouchers,
)

SIGNING_KEY_PATH = FilePath(__file__).sibling("testing-signing.key")


def get_rref(interface=None):
    if interface is None:
        interface = RIPrivacyPassAuthorizedStorageServer
    return LocalRemote(DummyReferenceable(interface))


class OpenStoreTests(TestCase):
    @skipIf(platform.isWindows(), "Hard to prevent directory creation on Windows")
    @given(tahoe_configs(), aware_datetimes())
    def test_uncreateable_store_directory(self, get_config, now):
        """
        If the underlying directory in the node configuration cannot be created
        then ``open_store`` raises ``StoreOpenError``.
        """
        nodedir = FilePath(self.useFixture(TempDir()).join("node"))

        # Create the node directory without permission to create the
        # underlying directory.
        mkdir(nodedir.path, 0o500)

        config = get_config(nodedir.path, "tub.port")
        db_path = FilePath(config.get_private_path(CONFIG_DB_NAME))

        self.assertThat(
            lambda: open_database(partial(connect, db_path.path)),
            Raises(
                AfterPreprocessing(
                    lambda exc_info: exc_info[1],
                    IsInstance(StoreOpenError),
                ),
            ),
        )

    @skipIf(
        platform.isWindows(), "Hard to prevent database from being opened on Windows"
    )
    def test_unopenable_database(self):
        """
        If the underlying database file cannot be opened then ``open_database``
        raises ``StoreOpenError``.
        """
        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()

        # Prevent further access to it.
        nodedir.child("private").chmod(0o000)
        db_path = nodedir.child("private").child(CONFIG_DB_NAME)

        self.assertThat(
            lambda: open_database(partial(connect, db_path.path)),
            raises(StoreOpenError),
        )


class GetRRefTests(TestCase):
    """
    Tests for ``get_rref``.
    """

    def test_localremote(self):
        """
        ``get_rref`` returns an instance of ``LocalRemote``.
        """
        rref = get_rref()
        self.assertThat(
            rref,
            IsInstance(LocalRemote),
        )

    def test_remote_interface(self):
        """
        ``get_rref`` returns an object which declares a remote interface matching
        the one given.
        """
        rref = get_rref()
        self.assertThat(
            rref,
            AfterPreprocessing(
                lambda ref: ref.tracker,
                MatchesStructure(
                    interfaceName=Equals(
                        RIPrivacyPassAuthorizedStorageServer.__remote_name__
                    ),
                ),
            ),
        )

    def test_default_remote_interface(self):
        """
        ``get_rref`` returns an object which declares a
        ``RIPrivacyPassAuthorizedStorageServer`` as the remote interface if no
        other interface is given.
        """
        rref = get_rref(RIStorageServer)
        self.assertThat(
            rref,
            AfterPreprocessing(
                lambda ref: ref.tracker,
                MatchesStructure(
                    interfaceName=Equals(RIStorageServer.__remote_name__),
                ),
            ),
        )


class PluginTests(TestCase):
    """
    Tests for ``twisted.plugins.zkapauthorizer.storage_server_plugin``.
    """

    def test_discoverable(self):
        """
        The plugin can be discovered.
        """
        self.assertThat(
            getPlugins(IFoolscapStoragePlugin),
            Contains(storage_server_plugin),
        )

    def test_provides_interface(self):
        """
        ``storage_server_plugin`` provides ``IFoolscapStoragePlugin``.
        """
        self.assertThat(
            storage_server_plugin,
            Provides([IFoolscapStoragePlugin]),
        )


def no_tahoe_client(reactor, node_config) -> ITahoeClient:
    """
    :raise: Always raise an exception.
    """
    raise Exception("No Tahoe client should be required in this context.")


@skipIf(platform.isWindows(), "Storage server is not supported on Windows")
class ServerPluginTests(TestCase):
    """
    Tests for the plugin's implementation of
    ``IFoolscapStoragePlugin.get_storage_server``.
    """

    def setup_example(self):
        self.reactor = MemoryReactorClock()
        self.plugin = ZKAPAuthorizer(NAME, self.reactor, no_tahoe_client)

    @given(server_configurations(SIGNING_KEY_PATH))
    def test_returns_announceable(self, configuration):
        """
        ``ZKAPAuthorizer.get_storage_server`` returns an instance which provides
        ``IAnnounceableStorageServer``.
        """
        storage_server_deferred = self.plugin.get_storage_server(
            configuration,
            get_anonymous_storage_server,
        )
        self.assertThat(
            storage_server_deferred,
            succeeded(Provides([IAnnounceableStorageServer])),
        )

    @given(server_configurations(SIGNING_KEY_PATH))
    def test_returns_referenceable(self, configuration):
        """
        The storage server attached to the result of
        ``ZKAPAuthorizer.get_storage_server`` provides ``IReferenceable`` and
        ``IRemotelyCallable``.
        """
        storage_server_deferred = self.plugin.get_storage_server(
            configuration,
            get_anonymous_storage_server,
        )
        self.assertThat(
            storage_server_deferred,
            succeeded(
                AfterPreprocessing(
                    lambda ann: ann.storage_server,
                    Provides([IReferenceable, IRemotelyCallable]),
                ),
            ),
        )

    @given(server_configurations(SIGNING_KEY_PATH))
    def test_returns_serializable(self, configuration):
        """
        The storage server attached to the result of
        ``ZKAPAuthorizer.get_storage_server`` can be serialized by a banana
        Broker (for Foolscap).
        """
        storage_server_deferred = self.plugin.get_storage_server(
            configuration,
            get_anonymous_storage_server,
        )
        broker = Broker(None)
        broker.makeConnection(StringTransport())
        self.expectThat(
            storage_server_deferred,
            succeeded(
                AfterPreprocessing(
                    lambda ann: broker.send(ann.storage_server),
                    Always(),
                ),
            ),
        )

    @given(server_configurations(SIGNING_KEY_PATH))
    def test_returns_hashable(self, configuration):
        """
        The storage server attached to the result of
        ``ZKAPAuthorizer.get_storage_server`` is hashable for use as a
        Python dictionary key.

        This is another requirement of Foolscap.
        """
        storage_server_deferred = self.plugin.get_storage_server(
            configuration,
            get_anonymous_storage_server,
        )
        broker = Broker(None)
        broker.makeConnection(StringTransport())
        self.expectThat(
            storage_server_deferred,
            succeeded(
                AfterPreprocessing(
                    lambda ann: hash(ann.storage_server),
                    Always(),
                ),
            ),
        )

    @given(timedeltas(min_value=timedelta(seconds=1)), posix_timestamps())
    def test_metrics_written(self, metrics_interval, when):
        """
        When the configuration tells us where to put a metrics .prom file
        and an interval how often to do so, test that metrics are actually
        written there after the configured interval.
        """
        self.reactor.advance(when)

        metrics_path = self.useFixture(TempDir()).join("metrics")
        configuration = {
            "prometheus-metrics-path": metrics_path,
            "prometheus-metrics-interval": str(int(metrics_interval.total_seconds())),
            "ristretto-issuer-root-url": "foo",
            "ristretto-signing-key-path": SIGNING_KEY_PATH.path,
        }
        announceable = extract_result(
            self.plugin.get_storage_server(
                configuration,
                get_anonymous_storage_server,
            )
        )
        registry = announceable.storage_server._registry

        g = Gauge("foo", "bar", registry=registry)
        for i in range(2):
            g.set(i)

            self.reactor.advance(metrics_interval.total_seconds())
            self.assertThat(
                metrics_path,
                has_metric(Equals("foo"), Equals(i)),
            )


class ServiceTests(TestCase):
    """
    Tests for the plugin's handling of a Twisted ``IServiceCollection``.
    """

    def test_started_and_stopped(self):
        """
        Children of ``ZKAPAuthorizer._service`` are started when the reactor
        starts and stopped when the reactor stops.
        """
        reactor = MemoryReactorClock()
        plugin = ZKAPAuthorizer(NAME, reactor, no_tahoe_client)

        # MemoryReactorClock does correctly implement callWhenRunning but it
        # does not implement shutdown hooks meaningfully... So instead of
        # asserting about the behavior we want, assert about how the plugin
        # pokes the reactor. :/ This is lame.  Maybe Twisted will make
        # MemoryReactorClock better.
        self.assertThat(
            reactor.whenRunningHooks,
            Equals([(plugin._service.startService, (), {})]),
        )
        self.assertThat(
            reactor.triggers,
            Equals({"before": {"shutdown": [(plugin._service.stopService, (), {})]}}),
        )

    @given(tahoe_configs().flatmap(just))
    def test_replicating(self, get_config) -> None:
        """
        There is a replication service for a database which has been placed into
        replication mode.
        """
        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        node_config = get_config(nodedir.path, "tub.port")
        grid = MemoryGrid()
        tahoe = grid.client(FilePath(node_config._basedir))

        # Place it into replication mode.
        self.assertThat(
            Deferred.fromCoroutine(setup_tahoe_lafs_replication(tahoe)),
            succeeded(Always()),
        )

        reactor = MemoryReactorClock()
        plugin = ZKAPAuthorizer(
            NAME,
            reactor,
            lambda reactor, config: grid.client(FilePath(config._basedir)),
        )

        # This causes MemoryReactorClock to run all the hooks, which
        # we need to actually get startService() called and
        # _replicating getting set
        reactor.run()

        # Let's make sure the service eventually stops.
        self.addCleanup(plugin._service.stopService)

        # There is no public interface for just getting the database
        # abstraction, so...
        store = plugin._get_store(node_config)
        self.assertThat(
            plugin._service,
            AnyMatch(
                MatchesPredicate(
                    lambda svc: service_matches(store, svc),
                    "not a replicating service with matching connection: %s",
                ),
            ),
        )

    def test_not_replicating(self) -> None:
        """
        There is not a replication service for a database which has not been
        placed into replication mode.
        """
        reactor = MemoryReactorClock()
        plugin = ZKAPAuthorizer(NAME, reactor, no_tahoe_client)

        self.assertThat(
            list(plugin._service),
            Equals([]),
        )


def service_matches(store: VoucherStore, svc: object) -> bool:
    """
    :return: ``True`` if ``svc`` is a replication service for the given
        store's database connection, ``False`` otherwise.
    """
    return (
        isinstance(svc, _ReplicationService)
        and svc._connection is store._connection
        and svc._connection._replicating
    )


def has_metric(name_matcher, value_matcher):
    """
    Create a matcher that matches a path that contains serialized metrics that
    include at least a single metric that is matched by the given
    ``name_matcher`` and ``value_matcher``.
    """

    def read_metrics(path):
        with open(path) as f:
            return list(text_string_to_metric_families(f.read()))

    return AfterPreprocessing(
        read_metrics,
        AnyMatch(
            MatchesStructure(
                name=name_matcher,
                samples=MatchesListwise(
                    [
                        MatchesStructure(
                            name=name_matcher,
                            value=value_matcher,
                        ),
                    ]
                ),
            ),
        ),
    )


tahoe_configs_with_dummy_redeemer = tahoe_configs(client_dummyredeemer_configurations())

tahoe_configs_with_mismatched_issuer = minimal_tahoe_configs(
    {
        NAME: just(
            {"ristretto-issuer-root-url": "https://another-issuer.example.invalid/"}
        ),
    }
)


class ClientPluginTests(TestCase):
    """
    Tests for the plugin's implementation of
    ``IFoolscapStoragePlugin.get_storage_client``.
    """

    def setUp(self):
        super().setUp()
        self.useFixture(DetectLeakedDescriptors())

    @given(tahoe_configs(), announcements())
    def test_interface(self, get_config, announcement):
        """
        ``get_storage_client`` returns an object which provides
        ``IStorageServer``.
        """
        reactor = MemoryReactorClock()
        plugin = ZKAPAuthorizer(NAME, reactor, no_tahoe_client)

        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()

        node_config = get_config(nodedir.path, "tub.port")

        storage_client = plugin.get_storage_client(
            node_config,
            announcement,
            get_rref,
        )

        self.assertThat(
            storage_client,
            Provides([IStorageServer]),
        )

    @given(tahoe_configs_with_mismatched_issuer, announcements())
    def test_mismatched_ristretto_issuer(self, config_text, announcement):
        """
        ``get_storage_client`` raises an exception when called with an
        announcement and local configuration which specify different issuers.
        """
        reactor = MemoryReactorClock()
        plugin = ZKAPAuthorizer(NAME, reactor, no_tahoe_client)

        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()

        node_config = config_from_string(
            nodedir.path,
            "tub.port",
            config_text.encode("utf-8"),
        )
        config_text = StringIO()
        node_config.config.write(config_text)
        self.addDetail("config", text_content(config_text.getvalue()))
        self.addDetail("announcement", text_content(str(announcement)))
        self.assertThat(
            lambda: plugin.get_storage_client(
                node_config,
                announcement,
                get_rref,
            ),
            raises(IssuerConfigurationMismatch),
        )

    @given(
        tahoe_configs(),
        announcements(),
        storage_indexes(),
        lease_renew_secrets(),
        lease_cancel_secrets(),
        sharenum_sets(),
        sizes(),
    )
    def test_mismatch_storage_server_furl(
        self,
        get_config,
        announcement,
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        size,
    ):
        """
        If the ``get_rref`` passed to ``get_storage_client`` returns a reference
        to something other than an ``RIPrivacyPassAuthorizedStorageServer``
        provider then the storage methods of the client raise exceptions that
        clearly indicate this.
        """
        reactor = MemoryReactorClock()
        plugin = ZKAPAuthorizer(NAME, reactor, no_tahoe_client)

        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()
        node_config = get_config(nodedir.path, "tub.port")

        storage_client = plugin.get_storage_client(
            node_config,
            announcement,
            partial(get_rref, RIStorageServer),
        )

        def use_it():
            return storage_client.allocate_buckets(
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                size,
                LocalReferenceable(None),
            )

        self.assertThat(
            use_it,
            raises(IncorrectStorageServerReference),
        )

    @given(
        get_config=tahoe_configs_with_dummy_redeemer,
        now=aware_datetimes(),
        announcement=announcements(),
        voucher=vouchers(),
        num_passes=pass_counts(),
        public_key=dummy_ristretto_keys(),
    )
    @capture_logging(lambda self, logger: logger.validate())
    def test_unblinded_tokens_spent(
        self,
        logger,
        get_config,
        now,
        announcement,
        voucher,
        num_passes,
        public_key,
    ):
        """
        The ``ZKAPAuthorizerStorageServer`` returned by ``get_storage_client``
        spends unblinded tokens from the plugin database.
        """
        reactor = MemoryReactorClock()
        plugin = ZKAPAuthorizer(NAME, reactor, no_tahoe_client)

        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()
        node_config = get_config(nodedir.path, "tub.port")

        # Populate the database with unspent tokens.
        def redeem():
            db_path = FilePath(node_config.get_private_path(CONFIG_DB_NAME))
            store = open_store(
                lambda: now, with_replication(connect(db_path.path), False), node_config
            )

            controller = PaymentController(
                store,
                DummyRedeemer(public_key),
                default_token_count=num_passes,
                num_redemption_groups=1,
                allowed_public_keys={public_key},
                clock=reactor,
            )
            # Get a token inserted into the store.
            return controller.redeem(voucher)

        self.assertThat(redeem(), succeeded(Always()))

        # Try to spend a pass via the storage client plugin.
        storage_client = plugin.get_storage_client(
            node_config,
            announcement,
            get_rref,
        )

        # None of the remote methods are implemented by our fake server and I
        # would like to continue to avoid to have a real server in these
        # tests, at least until creating a real server doesn't involve so much
        # complex setup.  So avoid using any of the client APIs that make a
        # remote call ... which is all of them.
        pass_group = storage_client._get_passes(b"request binding message", num_passes)
        pass_group.mark_spent()

        # There should be no unblinded tokens left to extract.
        self.assertThat(
            lambda: storage_client._get_passes(b"request binding message", 1),
            raises(NotEnoughTokens),
        )

        messages = LoggedMessage.of_type(logger.messages, GET_PASSES)
        self.assertThat(
            messages,
            MatchesAll(
                HasLength(1),
                AllMatch(
                    AfterPreprocessing(
                        lambda logged_message: logged_message.message,
                        ContainsDict(
                            {
                                "message": Equals("request binding message"),
                                "count": Equals(num_passes),
                            }
                        ),
                    ),
                ),
            ),
        )


class ClientResourceTests(TestCase):
    """
    Tests for the plugin's implementation of
    ``IFoolscapStoragePlugin.get_client_resource``.
    """

    def setup_example(self):
        self.reactor = MemoryReactorClock()
        self.grid = MemoryGrid()
        self.plugin = ZKAPAuthorizer(
            NAME, self.reactor, self.get_tahoe_client, memory_connect
        )

    def get_tahoe_client(self, reactor, node_config):
        return self.grid.client(FilePath(node_config._basedir))

    @given(tahoe_configs())
    def test_interface(self, get_config):
        """
        ``get_client_resource`` returns an object that provides ``IResource``.
        """
        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()
        config = get_config(nodedir.path, "tub.port")
        self.assertThat(
            self.plugin.get_client_resource(
                config,
            ),
            Provides([IResource]),
        )

    @given(tahoe_configs())
    def test_replication_service_created(self, get_config):
        """
        If replication is enabled using the ``IResource`` returned by
        ``get_client_resource`` then the plugin has a ``_ReplicationService``
        added to it.
        """
        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()
        config = get_config(nodedir.path, "tub.port")
        token = "hello world"
        with open(config.get_private_path("api_auth_token"), "w") as f:
            f.write(token)

        root = self.plugin.get_client_resource(config)

        agent = RequestTraversalAgent(root)
        self.assertThat(
            agent.request(
                b"POST",
                b"http://127.0.0.1/replicate",
                headers=Headers({"authorization": [f"tahoe-lafs {token}"]}),
            ),
            succeeded(matches_response(code_matcher=Equals(201))),
        )

        # This causes MemoryReactorClock to run all the hooks, which
        # we need to actually get startService() called and
        # _replicating getting set
        self.reactor.run()

        self.assertThat(
            self.plugin._service,
            AnyMatch(
                MatchesPredicate(
                    lambda svc: service_matches(self.plugin._get_store(config), svc),
                    "not a replicating service with matching connection: %s",
                ),
            ),
        )

    @given(tahoe_configs())
    def test_downloader(self, get_config):
        """
        The recovery resource is configured with a downloader that retrieves
        objects using the plugin's Tahoe-LAFS client.
        """
        # This test is too complicated.  The implementation should be factored so we can test what we want to test here without involving a Tahoe client, the plugin, and the client resource.
        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()
        config = get_config(nodedir.path, "tub.port")
        token = "hello world"
        with open(config.get_private_path("api_auth_token"), "w") as f:
            f.write(token)

        replica_dircap = self.grid.make_directory()
        self.grid.link(
            replica_dircap,
            "snapshot",
            self.grid.upload(statements_to_snapshot([])),
        )

        root = self.plugin.get_client_resource(config)

        # normally, we'd use Treq's machinery to do in-memory
        # requests, but this is a WebSocket, so we want to use
        # Autobahn's testing machinery. Maybe there's a clever way to
        # hook those together, but for now we reach in "directly" to
        # grab the WebSocketResource and set up Autobahn's test agent
        # that way (requiring the factory from the real resource)...
        wsr = get_recovery_websocket_resource(root)
        clock = MemoryReactorClockResolver()
        pumper = create_pumper()

        def create_proto():
            addr = IPv4Address("TCP", "127.0.0.1", "0")
            # use the _actual_ WebSocketResource's factory
            proto = wsr._factory.buildProtocol(addr)
            return proto

        agent = create_memory_agent(clock, pumper, create_proto)
        pumper.start()
        self.addCleanup(pumper.stop)

        recovering = Deferred.fromCoroutine(
            recover(
                agent, DecodedURL.from_text("ws://127.0.0.1:1/"), token, replica_dircap
            )
        )
        pumper._flush()

        self.assertThat(
            recovering,
            succeeded(
                Equals(
                    [
                        {"stage": "started", "failure-reason": None},
                        {"stage": "inspect_replica", "failure-reason": None},
                        {"stage": "downloading", "failure-reason": None},
                        {"stage": "succeeded", "failure-reason": None},
                    ],
                ),
            ),
        )


SERVERS_YAML = """
storage:
  v0-aaaaaaaa:
    ann:
      anonymous-storage-FURL: pb://@tcp:/
      nickname: 10.0.0.2
      storage-options:
      - name: {name}
        ristretto-issuer-root-url: https://payments.example.com/
        storage-server-FURL: pb://bbbbbbbb@tcp:10.0.0.2:1234/cccccccc
""".format(
    name=NAME
).encode(
    "ascii"
)

TWO_SERVERS_YAML = """
storage:
  v0-aaaaaaaa:
    ann:
      anonymous-storage-FURL: pb://@tcp:/
      nickname: 10.0.0.2
      storage-options:
      - name: {name}
        ristretto-issuer-root-url: https://payments.example.com/
        storage-server-FURL: pb://bbbbbbbb@tcp:10.0.0.2:1234/cccccccc
  v0-dddddddd:
    ann:
      anonymous-storage-FURL: pb://@tcp:/
      nickname: 10.0.0.3
      storage-options:
      - name: {name}
        ristretto-issuer-root-url: https://payments.example.com/
        storage-server-FURL: pb://eeeeeeee@tcp:10.0.0.3:1234/ffffffff
""".format(
    name=NAME
).encode(
    "ascii"
)


class LeaseMaintenanceServiceTests(TestCase):
    """
    Tests for the plugin's initialization of the lease maintenance service.
    """

    def setUp(self):
        super().setUp()
        self.useFixture(DetectLeakedDescriptors())

    def _create(self, get_config, servers_yaml, rootcap):
        """
        Create a client node using ``create_client_from_config``.

        :param get_config: A function to call to get a Tahoe-LAFS config
            object.

        :param servers_yaml: ``None`` or a string giving the contents for the
            node's ``servers.yaml`` file.

        :param rootcap: ``True`` to write some bytes to the node's ``rootcap``
            file, ``False`` otherwise.
        """
        nodedir = FilePath(self.useFixture(TempDir()).join("node"))
        nodedir.child("private").makedirs()
        config = get_config(nodedir.path, "tub.port")

        # In Tahoe-LAFS 1.17 write_private_config is broken.  It mixes bytes
        # and unicode in an os.path.join() call that always fails with a
        # TypeError.
        def write_private_config(name, value):
            privpath = FilePath(config._basedir).descendant(["private", name])
            privpath.setContent(value)

        if servers_yaml is not None:
            # Provide it a statically configured server to connect to.
            write_private_config(
                "servers.yaml",
                servers_yaml,
            )
        if rootcap:
            config.write_private_config(
                "rootcap",
                b"dddddddd",
            )

        return create_client_from_config(config)

    @given(minimal_tahoe_configs())
    def test_plugin_not_enabled(self, minimal_config):
        """
        If ZKAPAuthorizer storage client plugin isn't enabled then no lease
        maintenance service is created.
        """

        def get_config(basedir, portnumfile):
            return config_from_string(
                basedir, portnumfile, minimal_config.encode("utf-8")
            )

        d = self._create(get_config, servers_yaml=None, rootcap=False)
        self.assertThat(d, succeeded(Not(has_lease_maintenance_service())))

    @given(tahoe_configs())
    def test_get_root_nodes_rootcap_present(self, get_config):
        """
        ``get_root_nodes`` returns a ``list`` of one ``IFilesystemNode`` provider
        derived from the contents of the *rootcap* private configuration.
        """
        d = self._create(get_config, servers_yaml=None, rootcap=True)
        client_node = extract_result(d)
        roots = get_root_nodes(client_node, client_node.config)
        self.assertThat(
            roots,
            MatchesAll(
                HasLength(1),
                AllMatch(Provides([IFilesystemNode])),
            ),
        )

    @given(tahoe_configs())
    def test_get_root_nodes_rootcap_missing(self, get_config):
        """
        ``get_root_nodes`` returns an empty ``list`` if there is no private
        *rootcap* configuration.
        """
        d = self._create(get_config, servers_yaml=None, rootcap=False)
        client_node = extract_result(d)
        roots = get_root_nodes(client_node, client_node.config)
        self.assertThat(
            roots,
            Equals([]),
        )

    @settings(
        deadline=None,
    )
    @given(
        tahoe_configs_with_dummy_redeemer,
        sampled_from([SERVERS_YAML, TWO_SERVERS_YAML]),
    )
    def test_created(self, get_config, servers_yaml):
        """
        A client created from a configuration with the plugin enabled has a lease
        maintenance service after it has at least one storage server to
        connect to.
        """
        d = self._create(get_config, servers_yaml, rootcap=True)
        self.assertThat(d, succeeded(has_lease_maintenance_service()))

    @settings(
        deadline=None,
    )
    @given(
        tahoe_configs_with_dummy_redeemer,
        sampled_from([SERVERS_YAML, TWO_SERVERS_YAML]),
    )
    def test_created_without_rootcap(self, get_config, servers_yaml):
        """
        The lease maintenance service can be created even if no rootcap has yet
        been written to the client's configuration directory.
        """
        d = self._create(get_config, servers_yaml, rootcap=False)
        self.assertThat(d, succeeded(has_lease_maintenance_service()))

    @given(
        # First build the simple lease maintenance configuration object that
        # represents the example to test.
        lease_maintenance_configurations().flatmap(
            # Then build a function that will get us a Tahoe configuration
            # that includes at least that lease maintenance configuration.
            lambda lease_maint_config: tahoe_configs(
                zkapauthz_v2_configuration=client_lease_maintenance_configurations(
                    just(lease_maint_config),
                ),
            ).map(
                # Then bundle up both pieces to pass to the function.  By
                # preserving the lease maintenance configuration model object
                # and making it available to the test, the test logic is much
                # simplified (eg, we don't have to read values out of the
                # Tahoe configuration to figure out what example we're working
                # on).
                lambda get_config: (lease_maint_config, get_config),
            ),
        ),
    )
    def test_values_from_configuration(self, config_objs):
        """
        If values for lease maintenance parameters are supplied in the
        configuration file then the lease maintenance service is created with
        those values.
        """
        lease_maint_config, get_config = config_objs
        d = self._create(get_config, servers_yaml=None, rootcap=False)
        self.assertThat(
            d,
            succeeded(has_lease_maintenance_configuration(lease_maint_config)),
        )


def has_lease_maintenance_service() -> Matcher:
    """
    Return a matcher for a Tahoe-LAFS client object that has a lease
    maintenance service.
    """
    return AfterPreprocessing(
        lambda client: [service.name for service in client],
        Contains(SERVICE_NAME),
    )


def has_lease_maintenance_configuration(
    lease_maint_config: LeaseMaintenanceConfig,
) -> Matcher:
    """
    Return a matcher for a Tahoe-LAFS client object that has a lease
    maintenance service with the given configuration.
    """

    def get_lease_maintenance_config(lease_maint_service):
        return lease_maint_service.get_config()

    return AfterPreprocessing(
        lambda client: get_lease_maintenance_config(
            client.getServiceNamed(SERVICE_NAME),
        ),
        Equals(lease_maint_config),
    )


class LoadSigningKeyTests(TestCase):
    """
    Tests for ``load_signing_key``.
    """

    @given(ristretto_signing_keys())
    def test_valid(self, key_bytes):
        """
        A base64-encoded byte string representing a valid Ristretto signing key
        can be loaded from a file into a ``SigningKey`` object using
        ``load_signing_key``.

        :param bytes key: A base64-encoded Ristretto signing key.
        """
        p = FilePath(self.useFixture(TempDir()).join("key"))
        p.setContent(key_bytes)
        key = load_signing_key(p)
        self.assertThat(key, IsInstance(SigningKey))


class CostBasedPolicyTests(TestCase):
    """
    Tests for ``_CostBasedPolicy``.
    """

    @given(
        bytes_per_pass=integers(min_value=1),
        factor=floats(min_value=1, max_value=100),
        snapshot_size=integers(min_value=1),
        parameters=encoding_parameters(),
    )
    def test_should_snapshot(self, bytes_per_pass, factor, snapshot_size, parameters):
        """ """
        # Create a replica that has a storage cost that is more than the given
        # factor greater than the storage cost of the given snapshot.
        replica_sizes = [snapshot_size] * int(factor + 1)

        needed, happy, total = parameters
        policy = _CostBasedPolicy(
            bytes_per_pass=bytes_per_pass,
            encoding=ShareEncoding(needed, total),
            factor=factor,
        )
        self.assertThat(
            policy.should_snapshot(snapshot_size, replica_sizes),
            Equals(True),
        )

    @given(
        bytes_per_pass=integers(min_value=1),
        factor=floats(min_value=1, max_value=100),
        snapshot_size=integers(min_value=1),
        parameters=encoding_parameters(),
    )
    def test_should_not_snapshot(
        self, bytes_per_pass, factor, snapshot_size, parameters
    ):
        """ """
        # Create a replica that has a storage cost that is less than the given
        # factor greater than the storage cost of the given snapshot.
        replica_sizes = [snapshot_size] * int(factor - 1)

        needed, happy, total = parameters
        policy = _CostBasedPolicy(
            bytes_per_pass=bytes_per_pass,
            encoding=ShareEncoding(needed, total),
            factor=factor,
        )
        self.assertThat(
            policy.should_snapshot(snapshot_size, replica_sizes),
            Equals(False),
        )
