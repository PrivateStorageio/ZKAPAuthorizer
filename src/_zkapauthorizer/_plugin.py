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

from weakref import (
    WeakValueDictionary,
)

import attr

from zope.interface import (
    implementer,
)

from twisted.internet.defer import (
    succeed,
)

from allmydata.interfaces import (
    IFoolscapStoragePlugin,
    IAnnounceableStorageServer,
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

from .controller import (
    get_redeemer,
)

@implementer(IAnnounceableStorageServer)
@attr.s
class AnnounceableStorageServer(object):
    announcement = attr.ib()
    storage_server = attr.ib()


@attr.s
@implementer(IFoolscapStoragePlugin)
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
            s = VoucherStore.from_node_config(node_config)
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
        announcement = {
            u"ristretto-issuer-root-url": root_url,
        }
        storage_server = ZKAPAuthorizerStorageServer(
            get_anonymous_storage_server(),
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
        extract_unblinded_tokens = self._get_store(node_config).extract_unblinded_tokens
        def get_passes(message, count):
            unblinded_tokens = extract_unblinded_tokens(count)
            return redeemer.tokens_to_passes(message, unblinded_tokens)

        return ZKAPAuthorizerStorageClient(
            get_rref,
            get_passes,
        )


    def get_client_resource(self, node_config):
        from twisted.internet import reactor
        return resource_from_configuration(
            node_config,
            store=self._get_store(node_config),
            redeemer=self._get_redeemer(node_config, None, reactor),
        )
