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
from os import (
    makedirs,
)
import tempfile
from functools import (
    partial,
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
    Equals,
    AfterPreprocessing,
    MatchesAll,
    HasLength,
    AllMatch,
    ContainsDict,
)
from testtools.twistedsupport import (
    succeeded,
)
from testtools.content import (
    text_content,
)
from hypothesis import (
    given,
    settings,
)
from hypothesis.strategies import (
    just,
    datetimes,
    sampled_from,
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
from allmydata.client import (
    create_client_from_config,
)

from eliot.testing import (
    LoggedMessage,
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

from .._plugin import (
    GET_PASSES,
)

from ..foolscap import (
    RIPrivacyPassAuthorizedStorageServer,
)
from ..model import (
    NotEnoughTokens,
    VoucherStore,
)
from ..controller import (
    IssuerConfigurationMismatch,
    PaymentController,
    DummyRedeemer,
)
from ..storage_common import (
    required_passes,
    allocate_buckets_message,
)
from .._storage_client import (
    IncorrectStorageServerReference,
)

from ..lease_maintenance import (
    SERVICE_NAME,
)

from .strategies import (
    minimal_tahoe_configs,
    tahoe_configs,
    client_dummyredeemer_configurations,
    server_configurations,
    announcements,
    vouchers,
    storage_indexes,
    lease_renew_secrets,
    lease_cancel_secrets,
    sharenum_sets,
    sizes,
)
from .matchers import (
    Provides,
    raises,
)

from .foolscap import (
    LocalRemote,
    get_anonymous_storage_server,
    DummyReferenceable,
)

from .eliot import (
    capture_logging,
)



SIGNING_KEY_PATH = FilePath(__file__).sibling(u"testing-signing.key")


def get_rref(interface=None):
    if interface is None:
        interface = RIPrivacyPassAuthorizedStorageServer
    return LocalRemote(DummyReferenceable(interface))




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
        self.assertThat(
            lambda: storage_server.get_storage_client(
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
        tempdir = self.useFixture(TempDir())
        node_config = get_config(
            tempdir.join(b"node"),
            b"tub.port",
        )

        storage_client = storage_server.get_storage_client(
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
        now=datetimes(),
        announcement=announcements(),
        voucher=vouchers(),
        storage_index=storage_indexes(),
        renew_secret=lease_renew_secrets(),
        cancel_secret=lease_cancel_secrets(),
        sharenums=sharenum_sets(),
        size=sizes(),
    )
    @capture_logging(lambda self, logger: logger.validate())
    def test_unblinded_tokens_extracted(
            self,
            logger,
            get_config,
            now,
            announcement,
            voucher,
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

        # Give it enough for the allocate_buckets call below.
        token_count = required_passes(store.pass_value, [size] * len(sharenums))
        # And few enough redemption groups given the number of tokens.
        num_redemption_groups = token_count

        store = VoucherStore.from_node_config(node_config, lambda: now)
        controller = PaymentController(
            store,
            DummyRedeemer(),
            default_token_count=token_count,
            num_redemption_groups=num_redemption_groups,
        )
        # Get a token inserted into the store.
        redeeming = controller.redeem(voucher)
        self.assertThat(
            redeeming,
            succeeded(Always()),
        )

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
        self.assertThat(
            lambda: store.extract_unblinded_tokens(1),
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
                        ContainsDict({
                            u"message": Equals(allocate_buckets_message(storage_index)),
                            u"count": Equals(token_count),
                        }),
                    ),
                ),
            ),
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
            storage_server.get_client_resource(config, default_token_count=10),
            Provides([IResource]),
        )


SERVERS_YAML = b"""
storage:
  v0-aaaaaaaa:
    ann:
      anonymous-storage-FURL: pb://@tcp:/
      nickname: 10.0.0.2
      storage-options:
      - name: privatestorageio-zkapauthz-v1
        ristretto-issuer-root-url: https://payments.example.com/
        storage-server-FURL: pb://bbbbbbbb@tcp:10.0.0.2:1234/cccccccc
"""

TWO_SERVERS_YAML = b"""
storage:
  v0-aaaaaaaa:
    ann:
      anonymous-storage-FURL: pb://@tcp:/
      nickname: 10.0.0.2
      storage-options:
      - name: privatestorageio-zkapauthz-v1
        ristretto-issuer-root-url: https://payments.example.com/
        storage-server-FURL: pb://bbbbbbbb@tcp:10.0.0.2:1234/cccccccc
  v0-dddddddd:
    ann:
      anonymous-storage-FURL: pb://@tcp:/
      nickname: 10.0.0.3
      storage-options:
      - name: privatestorageio-zkapauthz-v1
        ristretto-issuer-root-url: https://payments.example.com/
        storage-server-FURL: pb://eeeeeeee@tcp:10.0.0.3:1234/ffffffff
"""


class LeaseMaintenanceServiceTests(TestCase):
    """
    Tests for the plugin's initialization of the lease maintenance service.
    """
    def _created_test(self, get_config, servers_yaml, rootcap):
        original_tempdir = tempfile.tempdir

        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")
        privatedir = tempdir.join(b"node", b"private")
        makedirs(privatedir)
        config = get_config(nodedir, b"tub.port")

        # Provide it a statically configured server to connect to.
        config.write_private_config(
            b"servers.yaml",
            servers_yaml,
        )
        if rootcap:
            config.write_private_config(
                b"rootcap",
                b"dddddddd",
            )

        try:
            d = create_client_from_config(config)
            self.assertThat(
                d,
                succeeded(
                    AfterPreprocessing(
                        lambda client: client.getServiceNamed(SERVICE_NAME),
                        Always(),
                    ),
                ),
            )
        finally:
            # create_client_from_config (indirectly) rewrites tempfile.tempdir
            # in a destructive manner that fails most of the rest of the test
            # suite if we don't clean it up.  We can't do this with a tearDown
            # or a fixture or an addCleanup because hypothesis doesn't run any
            # of those at the right time. :/
           tempfile.tempdir = original_tempdir

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
        return self._created_test(get_config, servers_yaml, rootcap=True)


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
        return self._created_test(get_config, servers_yaml, rootcap=False)
