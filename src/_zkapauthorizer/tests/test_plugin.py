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

from __future__ import (
    absolute_import,
)

from io import (
    BytesIO,
)

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
from testtools.content import (
    text_content,
)
from hypothesis import (
    given,
)
from hypothesis.strategies import (
    just,
    datetimes,
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

from twisted.python.filepath import (
    FilePath,
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
from ..controller import (
    IssuerConfigurationMismatch,
)

from .strategies import (
    minimal_tahoe_configs,
    tahoe_configs,
    client_dummyredeemer_configurations,
    server_configurations,
    announcements,
    vouchers,
    random_tokens,
    unblinded_tokens,
    storage_indexes,
    lease_renew_secrets,
    lease_cancel_secrets,
    sharenum_sets,
    sizes,
)
from .matchers import (
    Provides,
)


SIGNING_KEY_PATH = FilePath(__file__).sibling(u"testing-signing.key")


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
    @given(server_configurations(SIGNING_KEY_PATH))
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


    @given(server_configurations(SIGNING_KEY_PATH))
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

    @given(server_configurations(SIGNING_KEY_PATH))
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


    @given(server_configurations(SIGNING_KEY_PATH))
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


tahoe_configs_with_dummy_redeemer = tahoe_configs(client_dummyredeemer_configurations())

tahoe_configs_with_mismatched_issuer = minimal_tahoe_configs({
    u"privatestorageio-zkapauthz-v1": just({u"ristretto-issuer-root-url": u"https://another-issuer.example.invalid/"}),
})

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


    @given(tahoe_configs_with_mismatched_issuer, announcements())
    def test_mismatched_ristretto_issuer(self, get_config, announcement):
        """
        ``get_storage_client`` raises an exception when called with an
        announcement and local configuration which specify different issuers.
        """
        tempdir = self.useFixture(TempDir())
        node_config = get_config(
            tempdir.join(b"node"),
            b"tub.port",
        )
        config_text = BytesIO()
        node_config.config.write(config_text)
        self.addDetail(u"config", text_content(config_text.getvalue()))
        self.addDetail(u"announcement", text_content(unicode(announcement)))
        try:
            result = storage_server.get_storage_client(node_config, announcement, get_rref)
        except IssuerConfigurationMismatch:
            pass
        except Exception as e:
            self.fail("get_storage_client raised the wrong exception: {}".format(e))
        else:
            self.fail("get_storage_client didn't raise, returned: {}".format(result))


    @given(
        tahoe_configs_with_dummy_redeemer,
        datetimes(),
        announcements(),
        vouchers(),
        random_tokens(),
        unblinded_tokens(),
        storage_indexes(),
        lease_renew_secrets(),
        lease_cancel_secrets(),
        sharenum_sets(),
        sizes(),
    )
    def test_unblinded_tokens_extracted(
            self,
            get_config,
            now,
            announcement,
            voucher,
            token,
            unblinded_token,
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            size,
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

        store = VoucherStore.from_node_config(node_config, lambda: now)
        store.add(voucher, [token])
        store.insert_unblinded_tokens_for_voucher(voucher, [unblinded_token])

        storage_client = storage_server.get_storage_client(
            node_config,
            announcement,
            get_rref,
        )

        # For now, merely making the call spends the passes - regardless of
        # the ultimate success or failure of the operation.
        storage_client.allocate_buckets(
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            size,
            LocalReferenceable(None),
        )

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
