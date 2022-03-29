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
from typing import Callable
from weakref import WeakValueDictionary

from allmydata.client import _Client
from allmydata.interfaces import (
    IAnnounceableStorageServer,
    IFilesystemNode,
    IFoolscapStoragePlugin,
)
from allmydata.node import MissingConfigEntry
from attrs import Factory, define, field
from challenge_bypass_ristretto import PublicKey, SigningKey
from eliot import start_action
from prometheus_client import CollectorRegistry, write_to_textfile
from twisted.application.service import IService
from twisted.internet import task
from twisted.internet.defer import succeed
from twisted.logger import Logger
from twisted.python.filepath import FilePath
from zope.interface import implementer

from . import NAME
from .api import ZKAPAuthorizerStorageClient, ZKAPAuthorizerStorageServer
from .controller import get_redeemer
from .lease_maintenance import SERVICE_NAME as MAINTENANCE_SERVICE_NAME
from .lease_maintenance import (
    LeaseMaintenanceConfig,
    lease_maintenance_service,
    maintain_leases_from_root,
)
from .model import VoucherStore
from .recover import (
    make_fail_downloader,
)
from .replicate import (
    setup_tahoe_lafs_replication,
)
from .resource import from_configuration as resource_from_configuration
from .server.spending import get_spender
from .spending import SpendingController
from .storage_common import BYTES_PER_PASS, get_configured_pass_value
from .tahoe import get_tahoe_client

_log = Logger()


@implementer(IAnnounceableStorageServer)
@define
class AnnounceableStorageServer(object):
    announcement = field()
    storage_server = field()


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
    _stores: WeakValueDictionary = field(default=Factory(WeakValueDictionary))

    def _get_store(self, node_config):
        """
        :return VoucherStore: The database for the given node.  At most one
            connection is made to the database per ``ZKAPAuthorizer`` instance.
        """
        key = node_config.get_config_path()
        try:
            s = self._stores[key]
        except KeyError:
            s = VoucherStore.from_node_config(node_config, datetime.now)
            self._stores[key] = s
        return s

    def _get_redeemer(self, node_config, announcement, reactor):
        """
        :return IRedeemer: The voucher redeemer indicated by the given
            configuration.  A new instance is returned on every call because
            the redeemer interface is stateless.
        """
        return get_redeemer(self.name, node_config, announcement, reactor)

    def get_storage_server(
        self, configuration, get_anonymous_storage_server, reactor=None
    ):
        if reactor is None:
            from twisted.internet import reactor
        registry = CollectorRegistry()
        kwargs = configuration.copy()

        # If metrics are desired, schedule their writing to disk.
        metrics_interval = kwargs.pop("prometheus-metrics-interval", None)
        metrics_path = kwargs.pop("prometheus-metrics-path", None)
        if metrics_interval is not None and metrics_path is not None:
            FilePath(metrics_path).parent().makedirs(ignoreExistingDirectory=True)
            t = task.LoopingCall(make_safe_writer(metrics_path, registry))
            t.clock = reactor
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
            reactor=reactor,
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
        from twisted.internet import reactor

        redeemer = self._get_redeemer(node_config, announcement, reactor)
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

    def get_client_resource(self, node_config, reactor=None):
        """
        Get an ``IZKAPRoot`` for the given node configuration.

        :param allmydata.node._Config node_config: The configuration object
            for the relevant node.
        """
        if reactor is None:
            from twisted.internet import reactor

        work_in_progress_error = Exception(
            "The recovery system implementation is a work in progress.",
        )

        def get_downloader(cap):
            return make_fail_downloader(work_in_progress_error)

        setup_replication = partial(
            setup_tahoe_lafs_replication,
            get_tahoe_client(reactor, node_config),
        )

        return resource_from_configuration(
            node_config,
            store=self._get_store(node_config),
            get_downloader=get_downloader,
            ##            get_uploader=make_fail_uploader(work_in_progress_error),
            setup_replication=setup_replication,
            redeemer=self._get_redeemer(node_config, None, reactor),
            clock=reactor,
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
    for name, create in _SERVICES:
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


_SERVICES = [
    (MAINTENANCE_SERVICE_NAME, _create_maintenance_service),
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
storage_server_plugin = ZKAPAuthorizer(name=NAME)
