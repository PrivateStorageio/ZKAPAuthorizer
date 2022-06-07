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
The Twisted plugin that glues the Zero-Knowledge Access Pass system into
Tahoe-LAFS.
"""

import random
from datetime import datetime
from functools import partial
from sqlite3 import connect as _sqlite3_connect
from typing import Any, Callable
from weakref import WeakValueDictionary

from allmydata.client import _Client
from allmydata.interfaces import (
    IAnnounceableStorageServer,
    IFilesystemNode,
    IFoolscapStoragePlugin,
)
from allmydata.node import MissingConfigEntry
from attrs import Factory, define, field, frozen
from autobahn.twisted.resource import WebSocketResource
from challenge_bypass_ristretto import PublicKey, SigningKey
from eliot import start_action
from prometheus_client import CollectorRegistry, write_to_textfile
from twisted.application.service import IService, MultiService
from twisted.internet import task
from twisted.internet.defer import succeed
from twisted.logger import Logger
from twisted.python.filepath import FilePath
from twisted.web.guard import HTTPAuthSessionWrapper
from zope.interface import implementer

from . import NAME
from ._types import CapStr, GetTime
from .api import ZKAPAuthorizerStorageClient, ZKAPAuthorizerStorageServer
from .config import CONFIG_DB_NAME, Config
from .controller import get_redeemer
from .lease_maintenance import SERVICE_NAME as MAINTENANCE_SERVICE_NAME
from .lease_maintenance import (
    LeaseMaintenanceConfig,
    lease_maintenance_service,
    maintain_leases_from_root,
)
from .model import VoucherStore, aware_now
from .model import open_database as _open_database
from .recover import get_tahoe_lafs_downloader
from .replicate import (
    _ReplicationCapableConnection,
    get_replica_rwcap,
    get_tahoe_lafs_direntry_replica,
    is_replication_setup,
    replication_service,
    setup_tahoe_lafs_replication,
    with_replication,
)
from .resource import from_configuration as resource_from_configuration
from .server.spending import get_spender
from .spending import SpendingController
from .sql import UnboundConnect
from .storage_common import BYTES_PER_PASS, get_configured_pass_value
from .tahoe import (
    ITahoeClient,
    ShareEncoding,
    attenuate_writecap,
    get_tahoe_client,
    required_passes_for_data,
)

_log = Logger()


@implementer(IAnnounceableStorageServer)
@define
class AnnounceableStorageServer(object):
    announcement = field()
    storage_server = field()


def open_store(
    now: GetTime, conn: _ReplicationCapableConnection, node_config: Config
) -> VoucherStore:
    """
    Open a ``VoucherStore`` for the given configuration.

    :param now: A function that can be used to get the current time.

    :param conn: The database connection to give to the store.

    :param node_config: The Tahoe-LAFS configuration object for the node
        for which we want to open a store.

    :return: A new ``VoucherStore`` instance.
    """
    pass_value = get_configured_pass_value(node_config)
    return VoucherStore.from_connection(pass_value, now, conn)


@frozen
class _CostBasedPolicy:
    """
    Encode policy rules about when to take and upload a new snapshot.

    :ivar bytes_per_pass: The price of on-grid storage.
    :ivar encoding: The erasure encoding configuration used for all uploads.

    :ivar factor: A multiplier for how much more expensive must be to maintain
        the on-grid replica than it would be to maintain a replica based on a
        new snapshot before a new snapshot will be taken.
    """

    bytes_per_pass: int
    encoding: ShareEncoding
    factor: float

    def _required_passes(self, size: int) -> int:
        """
        Calculate the number of passes required to store an object of the given
        size, in bytes.
        """
        return required_passes_for_data(self.bytes_per_pass, self.encoding, size)

    def should_snapshot(self, snapshot_size: int, replica_sizes: list[int]) -> bool:
        """
        Decide to take a new snapshot if the cost to maintain the replica is
        greater than the new snapshot's cost by at least a factor of
        ``self.factor``.
        """
        snapshot_cost = self._required_passes(snapshot_size)
        replica_cost = sum(map(self._required_passes, replica_sizes))
        return snapshot_cost * self.factor < replica_cost


def get_recovery_websocket_resource(root: HTTPAuthSessionWrapper) -> WebSocketResource:
    """
    :returns: the resource that speaks the WebSocket recovery protocol
    """
    return root._portal.realm._root.children[b"recover"]


@implementer(IFoolscapStoragePlugin)
@define
class ZKAPAuthorizer(object):
    """
    A storage plugin which provides a token-based access control mechanism on
    top of the Tahoe-LAFS built-in storage server interface.

    :ivar _stores: A mapping from node directories to this plugin's database
        connections for those nodes.  The existence of any kind of attribute
        to reference database connections (not so much the fact that it is a
        WeakValueDictionary; if it were just a weakref the same would be true)
        probably reflects an error in the interface which forces different
        methods to use instance state to share a database connection.
    """

    name: str
    reactor: Any
    _get_tahoe_client: Callable[[Any, Config], ITahoeClient]
    # UnboundConnect doesn't actually unify with sqlite3.connect at the
    # moment.  Can't be bothered to fix it right now.
    _connect: UnboundConnect = _sqlite3_connect  # type: ignore

    _stores: WeakValueDictionary = Factory(WeakValueDictionary)
    _service: MultiService = field()

    @_service.default
    def _service_default(self):
        svc = MultiService()
        # There doesn't seem to be an API in Twisted to hook a service up to
        # the reactor.  There are pieces of it but they're spread out and
        # mixed with other stuff.  So, just do it ourselves.  See
        # twisted.application.app.startApplication for some of it, if you
        # want.
        #
        # We intentionally don't hook up privilegedStartService because
        # there's no expectation of a requirement for privileged operations
        # and because we don't expect to ever run with any privileges and
        # because we never expect to try to shed any privileges.
        self.reactor.callWhenRunning(svc.startService)
        self.reactor.addSystemEventTrigger("before", "shutdown", svc.stopService)
        return svc

    def _get_store(self, node_config: Config) -> VoucherStore:
        """
        :return: The ``VoucherStore`` for the given node.  At most one connection
            is made to the database per ``ZKAPAuthorizer`` instance.
        """
        key = node_config.get_config_path()
        try:
            store = self._stores[key]
        except KeyError:
            db_path = FilePath(node_config.get_private_path(CONFIG_DB_NAME))
            unreplicated_conn = _open_database(partial(self._connect, db_path.path))
            replicated_conn = with_replication(
                unreplicated_conn, is_replication_setup(node_config)
            )
            store = open_store(aware_now, replicated_conn, node_config)

            if is_replication_setup(node_config):
                self._add_replication_service(replicated_conn, node_config)
            self._stores[key] = store
        return store

    def _add_replication_service(
        self, replicated_conn: _ReplicationCapableConnection, node_config: Config
    ) -> CapStr:
        """
        Create a replication service for the given database and arrange for it to
        start and stop when the reactor starts and stops.
        """
        client = self._get_tahoe_client(self.reactor, node_config)
        mutable = get_replica_rwcap(node_config)
        replica = get_tahoe_lafs_direntry_replica(client, mutable)
        cost = _CostBasedPolicy(
            get_configured_pass_value(node_config),
            client.get_config().encoding,
            10,
        )
        replication_service(replicated_conn, replica, cost).setServiceParent(
            self._service
        )
        return mutable

    def _get_redeemer(self, node_config, announcement):
        """
        :return IRedeemer: The voucher redeemer indicated by the given
            configuration.  A new instance is returned on every call because
            the redeemer interface is stateless.
        """
        return get_redeemer(self.name, node_config, announcement, self.reactor)

    def get_storage_server(self, configuration, get_anonymous_storage_server):
        registry = CollectorRegistry()
        kwargs = configuration.copy()

        # If metrics are desired, schedule their writing to disk.
        metrics_interval = kwargs.pop("prometheus-metrics-interval", None)
        metrics_path = kwargs.pop("prometheus-metrics-path", None)
        if metrics_interval is not None and metrics_path is not None:
            FilePath(metrics_path).parent().makedirs(ignoreExistingDirectory=True)
            t = task.LoopingCall(make_safe_writer(metrics_path, registry))
            t.clock = self.reactor
            t.start(int(metrics_interval))

        root_url = kwargs.pop("ristretto-issuer-root-url")
        pass_value = int(kwargs.pop("pass-value", BYTES_PER_PASS))
        signing_key = load_signing_key(
            FilePath(
                kwargs.pop("ristretto-signing-key-path"),
            ),
        )
        public_key = PublicKey.from_signing_key(signing_key)
        announcement = {
            "ristretto-issuer-root-url": root_url,
            "ristretto-public-keys": [public_key.encode_base64()],
        }
        anonymous_storage_server = get_anonymous_storage_server()
        spender = get_spender(
            config=kwargs,
            reactor=self.reactor,
            registry=registry,
        )
        storage_server = ZKAPAuthorizerStorageServer(
            anonymous_storage_server,
            pass_value=pass_value,
            signing_key=signing_key,
            spender=spender,
            registry=registry,
            **kwargs,
        )
        return succeed(
            AnnounceableStorageServer(
                announcement,
                storage_server,
            ),
        )

    def get_storage_client(self, node_config, announcement, get_rref):
        """
        Create an ``IStorageClient`` that submits ZKAPs with certain requests in
        order to authorize them.  The ZKAPs are extracted from the database
        managed by this plugin in the node directory that goes along with
        ``node_config``.
        """
        redeemer = self._get_redeemer(node_config, announcement)
        store = self._get_store(node_config)
        controller = SpendingController.for_store(
            tokens_to_passes=redeemer.tokens_to_passes,
            store=store,
        )
        return ZKAPAuthorizerStorageClient(
            get_configured_pass_value(node_config),
            get_rref,
            controller.get,
        )

    def get_client_resource(self, node_config):
        """
        Get an ``IZKAPRoot`` for the given node configuration.

        :param allmydata.node._Config node_config: The configuration object
            for the relevant node.
        """
        store = self._get_store(node_config)
        tahoe = self._get_tahoe_client(self.reactor, node_config)

        async def setup_replication():
            # Setup replication
            await setup_tahoe_lafs_replication(tahoe)
            # And then turn replication on for the database connection already
            # in use.
            mutable = self._add_replication_service(store._connection, node_config)
            return attenuate_writecap(mutable)

        return resource_from_configuration(
            node_config,
            store=store,
            get_downloader=get_tahoe_lafs_downloader(tahoe),
            setup_replication=setup_replication,
            redeemer=self._get_redeemer(node_config, None),
            clock=self.reactor,
        )


def make_safe_writer(
    metrics_path: str, registry: CollectorRegistry
) -> Callable[[], None]:
    """
    Make a no-argument callable that writes metrics from the given registry to
    the given path.  The callable will log errors writing to the path and not
    raise exceptions.
    """

    def safe_writer():
        try:
            with start_action(
                action_type="zkapauthorizer:metrics:write-to-textfile",
                metrics_path=metrics_path,
            ):
                write_to_textfile(metrics_path, registry)
        except Exception:
            pass

    return safe_writer


_init_storage = _Client.__dict__["init_storage"]


def _attach_zkapauthorizer_services(self, announceable_storage_servers):
    """
    A monkey-patched version of ``_Client.init_storage`` which also
    initializes ZKAPAuthorizer's services.
    """
    from twisted.internet import reactor

    # Make sure the original work happens.
    result = _init_storage(self, announceable_storage_servers)

    # Find the database relevant to this node.  The global state, the weakref
    # lookup... these things are not great.
    store = storage_server_plugin._get_store(self.config)

    # Hook up our services.
    for name, predicate, create in _SERVICES:
        if predicate(self.config):
            _maybe_attach_service(
                reactor,
                self,
                store,
                name,
                create,
            )

    return result


_Client.init_storage = _attach_zkapauthorizer_services


def _maybe_attach_service(
    reactor, client_node, store: VoucherStore, name: str, make_service
) -> None:
    """
    Check for an existing service and if one is not found create one and
    attach it to the client service.

    :param allmydata.client._Client client_node: The client node to check and,
        possibly, modify.  A lease maintenance service is added to it if and
        only if one is not already present.
    """
    try:
        # If there is already one we don't need another.
        client_node.getServiceNamed(name)
    except KeyError:
        # There isn't one so make it and add it.
        _log.info(f"Creating new {name} service")
        try:
            service = make_service(
                reactor,
                client_node,
                store,
            )
        except:
            _log.failure(f"Attaching {name} service to client node")
        else:
            service.setServiceParent(client_node)
    else:
        _log.info(f"Found existing {name} service")


def _create_maintenance_service(reactor, client_node, store: VoucherStore) -> IService:
    """
    Create a lease maintenance service to be attached to the given client
    node.

    :param allmydata.client._Client client_node: The client node the lease
        maintenance service will be attached to.
    """
    node_config = client_node.config

    def get_now():
        return datetime.utcfromtimestamp(reactor.seconds())

    maint_config = LeaseMaintenanceConfig.from_node_config(node_config)

    # Create the operation which performs the lease maintenance job when
    # called.
    maintain_leases = maintain_leases_from_root(
        get_root_nodes=partial(get_root_nodes, client_node, node_config),
        storage_broker=client_node.get_storage_broker(),
        secret_holder=client_node._secret_holder,
        min_lease_remaining=maint_config.min_lease_remaining,
        progress=store.start_lease_maintenance,
        get_now=get_now,
    )
    last_run_path = FilePath(node_config.get_private_path("last-lease-maintenance-run"))
    # Create the service to periodically run the lease maintenance operation.
    return lease_maintenance_service(
        maintain_leases,
        reactor,
        last_run_path,
        random,
        lease_maint_config=maint_config,
    )


def _is_client_plugin_enabled(node_config: Config) -> bool:
    """
    :return: ``True`` if and only if the ZKAPAuthorizer storage client plugin
        is enabled in the given configuration.
    """
    # See allmydata/storage_client.py, StorageClientConfig.from_node_config.
    storage_plugins = node_config.get_config("client", "storage.plugins", "")
    plugin_names = {name.strip() for name in storage_plugins.split(",")}
    return NAME in plugin_names


_SERVICES = [
    # Run the lease maintenance service on client nodes.
    (MAINTENANCE_SERVICE_NAME, _is_client_plugin_enabled, _create_maintenance_service),
]


def get_root_nodes(client_node, node_config) -> list[IFilesystemNode]:
    """
    Get the configured starting points for lease maintenance traversal.
    """
    try:
        rootcap = node_config.get_private_config("rootcap")
    except MissingConfigEntry:
        return []
    else:
        return [client_node.create_node_from_uri(rootcap.encode("utf-8"))]


def load_signing_key(path):
    """
    Read a serialized Ristretto signing key from the given path and return it
    as a ``challenge_bypass_ristretto.SigningKey``.

    Unlike ``challenge_bypass_ristretto.SigningKey.decode_base64`` this
    function will clean up any whitespace around the key.

    :param FilePath path: The path from which to read the key.

    :raise challenge_bypass_ristretto.DecodeException: If
        ``SigningKey.decode_base64`` raises this exception it will be passed
        through.

    :return challenge_bypass_ristretto.SigningKey: An object representing the
        key read.
    """
    return SigningKey.decode_base64(path.getContent().strip())


# Create the global plugin object, re-exported elsewhere so Twisted can
# discover it.  We'll also use it here since it carries some state that we
# sometimes need to dig up and can't easily get otherwise.
def _create_plugin():
    # Do not leak the global reactor into the module scope!
    from twisted.internet import reactor

    return ZKAPAuthorizer(
        name=NAME,
        reactor=reactor,
        get_tahoe_client=get_tahoe_client,
    )


storage_server_plugin = _create_plugin()
