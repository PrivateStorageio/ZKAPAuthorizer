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

from zope.interface import (
    implementer,
)

from fixtures import (
    TempDir,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    Always,
    Contains,
    AfterPreprocessing,
    Equals,
)
from testtools.twistedsupport import (
    succeeded,
)

from hypothesis import (
    given,
)

from foolscap.broker import (
    Broker,
)
from foolscap.ipb import (
    IReferenceable,
    IRemotelyCallable,
)
from foolscap.referenceable import (
    LocalReferenceable,
)

from allmydata.interfaces import (
    IFoolscapStoragePlugin,
    IAnnounceableStorageServer,
    IStorageServer,
    RIStorageServer,
)

from twisted.plugin import (
    getPlugins,
)
from twisted.test.proto_helpers import (
    StringTransport,
)
from twisted.web.resource import (
    IResource,
)
from twisted.plugins.zkapauthorizer import (
    storage_server,
)

from ..model import (
    VoucherStore,
)

from .strategies import (
    tahoe_configs,
    configurations,
    announcements,
    vouchers,
    random_tokens,
    unblinded_tokens,
    storage_indexes,
    lease_renew_secrets,
)
from .matchers import (
    Provides,
)


@implementer(RIStorageServer)
class StubStorageServer(object):
    pass


def get_anonymous_storage_server():
    return StubStorageServer()


def get_rref():
    return LocalReferenceable(None)


class PluginTests(TestCase):
    """
    Tests for ``twisted.plugins.zkapauthorizer.storage_server``.
    """
    def test_discoverable(self):
        """
        The plugin can be discovered.
        """
        self.assertThat(
            getPlugins(IFoolscapStoragePlugin),
            Contains(storage_server),
        )


    def test_provides_interface(self):
        """
        ``storage_server`` provides ``IFoolscapStoragePlugin``.
        """
        self.assertThat(
            storage_server,
            Provides([IFoolscapStoragePlugin]),
        )



class ServerPluginTests(TestCase):
    """
    Tests for the plugin's implementation of
    ``IFoolscapStoragePlugin.get_storage_server``.
    """
    @given(configurations())
    def test_returns_announceable(self, configuration):
        """
        ``storage_server.get_storage_server`` returns an instance which provides
        ``IAnnounceableStorageServer``.
        """
        storage_server_deferred = storage_server.get_storage_server(
            configuration,
            get_anonymous_storage_server,
        )
        self.assertThat(
            storage_server_deferred,
            succeeded(Provides([IAnnounceableStorageServer])),
        )


    @given(configurations())
    def test_returns_referenceable(self, configuration):
        """
        The storage server attached to the result of
        ``storage_server.get_storage_server`` provides ``IReferenceable`` and
        ``IRemotelyCallable``.
        """
        storage_server_deferred = storage_server.get_storage_server(
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

    @given(configurations())
    def test_returns_serializable(self, configuration):
        """
        The storage server attached to the result of
        ``storage_server.get_storage_server`` can be serialized by a banana
        Broker (for Foolscap).
        """
        storage_server_deferred = storage_server.get_storage_server(
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


    @given(configurations())
    def test_returns_hashable(self, configuration):
        """
        The storage server attached to the result of
        ``storage_server.get_storage_server`` is hashable for use as a Python
        dictionary key.

        This is another requirement of Foolscap.
        """
        storage_server_deferred = storage_server.get_storage_server(
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



class ClientPluginTests(TestCase):
    """
    Tests for the plugin's implementation of
    ``IFoolscapStoragePlugin.get_storage_client``.
    """
    @given(tahoe_configs(), announcements())
    def test_interface(self, get_config, announcement):
        """
        ``get_storage_client`` returns an object which provides
        ``IStorageServer``.
        """
        tempdir = self.useFixture(TempDir())
        node_config = get_config(
            tempdir.join(b"node"),
            b"tub.port",
        )

        storage_client = storage_server.get_storage_client(
            node_config,
            announcement,
            get_rref,
        )

        self.assertThat(
            storage_client,
            Provides([IStorageServer]),
        )


    @given(
        tahoe_configs(),
        announcements(),
        vouchers(),
        random_tokens(),
        unblinded_tokens(),
        storage_indexes(),
        lease_renew_secrets(),
    )
    def test_unblinded_tokens_extracted(
            self,
            get_config,
            announcement,
            voucher,
            token,
            unblinded_token,
            storage_index,
            renew_secret,
    ):
        """
        The ``ZKAPAuthorizerStorageServer`` returned by ``get_storage_client``
        extracts unblinded tokens from the plugin database.
        """
        tempdir = self.useFixture(TempDir())
        node_config = get_config(
            tempdir.join(b"node"),
            b"tub.port",
        )

        store = VoucherStore.from_node_config(node_config)
        store.add(voucher, [token])
        store.insert_unblinded_tokens_for_voucher(voucher, [unblinded_token])

        storage_client = storage_server.get_storage_client(
            node_config,
            announcement,
            get_rref,
        )

        # This is hooked up to a garbage reference.  We don't care about its
        # _result_, anyway, right now.
        d = storage_client.renew_lease(
            storage_index,
            renew_secret,
        )
        d.addBoth(lambda ignored: None)

        # There should be no unblinded tokens left to extract.
        remaining = store.extract_unblinded_tokens(1)
        self.assertThat(
            remaining,
            Equals([]),
        )


class ClientResourceTests(TestCase):
    """
    Tests for the plugin's implementation of
    ``IFoolscapStoragePlugin.get_client_resource``.
    """
    @given(tahoe_configs())
    def test_interface(self, get_config):
        """
        ``get_client_resource`` returns an object that provides ``IResource``.
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")
        config = get_config(nodedir, b"tub.port")
        self.assertThat(
            storage_server.get_client_resource(config),
            Provides([IResource]),
        )
