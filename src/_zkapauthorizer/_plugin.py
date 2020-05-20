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
from weakref import (
    WeakValueDictionary,
)
from datetime import (
    datetime,
    timedelta,
)
from functools import (
    partial,
)

import attr

from zope.interface import (
    implementer,
)

from twisted.logger import (
    Logger,
)
from twisted.python.filepath import (
    FilePath,
)
from twisted.internet.defer import (
    succeed,
)

from allmydata.interfaces import (
    IFoolscapStoragePlugin,
    IAnnounceableStorageServer,
)
from allmydata.node import (
    MissingConfigEntry,
)
from allmydata.client import (
    _Client,
)
from challenge_bypass_ristretto import (
    SigningKey,
)

from .api import (
    ZKAPAuthorizerStorageServer,
    ZKAPAuthorizerStorageClient,
)

from .model import (
    VoucherStore,
)

from .resource import (
    from_configuration as resource_from_configuration,
)
from .storage_common import (
    BYTES_PER_PASS,
    get_configured_pass_value,
)
from .controller import (
    get_redeemer,
)
from .spending import (
    SpendingController,
)

from .lease_maintenance import (
    SERVICE_NAME,
    lease_maintenance_service,
    maintain_leases_from_root,
)

_log = Logger()

@implementer(IAnnounceableStorageServer)
@attr.s
class AnnounceableStorageServer(object):
    announcement = attr.ib()
    storage_server = attr.ib()


@implementer(IFoolscapStoragePlugin)
@attr.s
class ZKAPAuthorizer(object):
    """
    A storage plugin which provides a token-based access control mechanism on
    top of the Tahoe-LAFS built-in storage server interface.

    :ivar WeakValueDictionary _stores: A mapping from node directories to this
        plugin's database connections for those nodes.  The existence of any
        kind of attribute to reference database connections (not so much the
        fact that it is a WeakValueDictionary; if it were just a weakref the
        same would be true) probably reflects an error in the interface which
        forces different methods to use instance state to share a database
        connection.
    """
    name = attr.ib(default=u"privatestorageio-zkapauthz-v1")
    _stores = attr.ib(default=attr.Factory(WeakValueDictionary))

    def _get_store(self, node_config):
        """
        :return VoucherStore: The database for the given node.  At most one
            connection is made to the database per ``ZKAPAuthorizer`` instance.
        """
        key =  node_config.get_config_path()
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


    def get_storage_server(self, configuration, get_anonymous_storage_server):
        kwargs = configuration.copy()
        root_url = kwargs.pop(u"ristretto-issuer-root-url")
        pass_value = kwargs.pop(u"pass-value", BYTES_PER_PASS)
        signing_key = SigningKey.decode_base64(
            FilePath(
                kwargs.pop(u"ristretto-signing-key-path"),
            ).getContent(),
        )
        announcement = {
            u"ristretto-issuer-root-url": root_url,
        }
        storage_server = ZKAPAuthorizerStorageServer(
            get_anonymous_storage_server(),
            pass_value=pass_value,
            signing_key=signing_key,
            **kwargs
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
        # XXX Need to ensure one of these per store
        controller = SpendingController(
            store.extract_unblinded_tokens,
            redeemer.tokens_to_passes,
        )
        get_passes = controller.get
        return ZKAPAuthorizerStorageClient(
            get_configured_pass_value(node_config),
            get_rref,
            get_passes,
        )


    def get_client_resource(self, node_config, default_token_count=None):
        """
        Get an ``IZKAPRoot`` for the given node configuration.

        :param allmydata.node._Config node_config: The configuration object
            for the relevant node.

        :param int default_token_count: Configure the payment controller with
            a default number of tokens to request during voucher redemption.
            This is only used if a number of tokens isn't specified at the
            point of redemption.
        """
        from twisted.internet import reactor
        return resource_from_configuration(
            node_config,
            store=self._get_store(node_config),
            redeemer=self._get_redeemer(node_config, None, reactor),
            default_token_count=default_token_count,
        )


_init_storage = _Client.__dict__["init_storage"]
def maintenance_init_storage(self, announceable_storage_servers):
    """
    A monkey-patched version of ``_Client.init_storage`` which also
    initializes the lease maintenance service.
    """
    from twisted.internet import reactor
    result = _init_storage(self, announceable_storage_servers)
    _maybe_attach_maintenance_service(reactor, self)
    return result
_Client.init_storage = maintenance_init_storage


def _maybe_attach_maintenance_service(reactor, client_node):
    """
    Check for an existing lease maintenance service and if one is not found,
    create one.

    :param allmydata.client._Client client_node: The client node to check and,
        possibly, modify.  A lease maintenance service is added to it if and
        only if one is not already present.
    """
    try:
        # If there is already one we don't need another.
        client_node.getServiceNamed(SERVICE_NAME)
    except KeyError:
        # There isn't one so make it and add it.
        _log.info("Creating new lease maintenance service")
        _create_maintenance_service(
            reactor,
            client_node.config,
            client_node,
        ).setServiceParent(client_node)
    except Exception:
        _log.failure("Attaching maintenance service to client node")
    else:
        _log.info("Found existing lease maintenance service")


def _create_maintenance_service(reactor, node_config, client_node):
    """
    Create a lease maintenance service to be attached to the given client
    node.

    :param allmydata.node._Config node_config: The configuration for the node
        the lease maintenance service will be attached to.

    :param allmydata.client._Client client_node: The client node the lease
        maintenance service will be attached to.
    """
    def get_now():
        return datetime.utcfromtimestamp(reactor.seconds())

    from twisted.plugins.zkapauthorizer import (
        storage_server,
    )
    store = storage_server._get_store(node_config)

    # Create the operation which performs the lease maintenance job when
    # called.
    maintain_leases = maintain_leases_from_root(
        partial(get_root_nodes, client_node, node_config),
        client_node.get_storage_broker(),
        client_node._secret_holder,
        # Make this configuration
        timedelta(days=3),
        store.start_lease_maintenance,
        get_now,
    )
    last_run_path = FilePath(node_config.get_private_path(b"last-lease-maintenance-run"))
    # Create the service to periodically run the lease maintenance operation.
    return lease_maintenance_service(
        maintain_leases,
        reactor,
        last_run_path,
        random,
    )


def get_root_nodes(client_node, node_config):
    try:
        rootcap = node_config.get_private_config(b"rootcap")
    except MissingConfigEntry:
        return []
    else:
        return [client_node.create_node_from_uri(rootcap)]
