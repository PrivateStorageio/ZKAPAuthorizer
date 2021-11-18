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

from __future__ import absolute_import

import tempfile
from functools import partial
from os import makedirs

from allmydata.client import config_from_string, create_client_from_config
from allmydata.interfaces import (
    IAnnounceableStorageServer,
    IFoolscapStoragePlugin,
    IStorageServer,
    RIStorageServer,
)
from challenge_bypass_ristretto import SigningKey
from eliot.testing import LoggedMessage
from fixtures import TempDir
from foolscap.broker import Broker
from foolscap.ipb import IReferenceable, IRemotelyCallable
from foolscap.referenceable import LocalReferenceable
from hypothesis import given, settings
from hypothesis.strategies import datetimes, just, sampled_from
from StringIO import StringIO
from testtools import TestCase
from testtools.content import text_content
from testtools.matchers import (
    AfterPreprocessing,
    AllMatch,
    Always,
    Contains,
    ContainsDict,
    Equals,
    HasLength,
    IsInstance,
    MatchesAll,
    MatchesStructure,
)
from testtools.twistedsupport import succeeded
from twisted.internet.task import Clock
from twisted.plugin import getPlugins
from twisted.python.filepath import FilePath
from twisted.test.proto_helpers import StringTransport
from twisted.web.resource import IResource

from twisted.plugins.zkapauthorizer import storage_server

from .._plugin import load_signing_key
from .._storage_client import IncorrectStorageServerReference
from ..controller import DummyRedeemer, IssuerConfigurationMismatch, PaymentController
from ..foolscap import RIPrivacyPassAuthorizedStorageServer
from ..lease_maintenance import SERVICE_NAME
from ..model import NotEnoughTokens, VoucherStore
from ..spending import GET_PASSES
from .eliot import capture_logging
from .foolscap import DummyReferenceable, LocalRemote, get_anonymous_storage_server
from .matchers import Provides, raises
from .strategies import (
    announcements,
    client_dummyredeemer_configurations,
    client_lease_maintenance_configurations,
    dummy_ristretto_keys,
    lease_cancel_secrets,
    lease_maintenance_configurations,
    lease_renew_secrets,
    minimal_tahoe_configs,
    pass_counts,
    ristretto_signing_keys,
    server_configurations,
    sharenum_sets,
    sizes,
    storage_indexes,
    tahoe_configs,
    vouchers,
)

SIGNING_KEY_PATH = FilePath(__file__).sibling(u"testing-signing.key")


def get_rref(interface=None):
    if interface is None:
        interface = RIPrivacyPassAuthorizedStorageServer
    return LocalRemote(DummyReferenceable(interface))


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

tahoe_configs_with_mismatched_issuer = minimal_tahoe_configs(
    {
        u"privatestorageio-zkapauthz-v1": just(
            {u"ristretto-issuer-root-url": u"https://another-issuer.example.invalid/"}
        ),
    }
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

    @given(tahoe_configs_with_mismatched_issuer, announcements())
    def test_mismatched_ristretto_issuer(self, config_text, announcement):
        """
        ``get_storage_client`` raises an exception when called with an
        announcement and local configuration which specify different issuers.
        """
        tempdir = self.useFixture(TempDir())
        node_config = config_from_string(
            tempdir.join(b"node"),
            b"tub.port",
            config_text.encode("utf-8"),
        )
        # On Tahoe-LAFS <1.16, the config is written as bytes.
        # On Tahoe-LAFS >=1.16, the config is written as unicode.
        #
        # So we'll use `StringIO.StringIO` (not `io.StringIO`) here - which
        # will allow either type (it will also implicitly decode bytes to
        # unicode if we mix them, though I don't think that should happen
        # here).
        #
        # After support for Tahoe <1.16 support is dropped we probably want to
        # switch to an io.StringIO here.
        config_text = StringIO()
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
        tempdir = self.useFixture(TempDir())
        node_config = get_config(
            tempdir.join(b"node"),
            b"tub.port",
        )

        store = VoucherStore.from_node_config(node_config, lambda: now)

        controller = PaymentController(
            store,
            DummyRedeemer(public_key),
            default_token_count=num_passes,
            num_redemption_groups=1,
            allowed_public_keys={public_key},
            clock=Clock(),
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

        # None of the remote methods are implemented by our fake server and I
        # would like to continue to avoid to have a real server in these
        # tests, at least until creating a real server doesn't involve so much
        # complex setup.  So avoid using any of the client APIs that make a
        # remote call ... which is all of them.
        pass_group = storage_client._get_passes(u"request binding message", num_passes)
        pass_group.mark_spent()

        # There should be no unblinded tokens left to extract.
        self.assertThat(
            lambda: storage_client._get_passes(u"request binding message", 1),
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
                                u"message": Equals(u"request binding message"),
                                u"count": Equals(num_passes),
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

    @given(tahoe_configs())
    def test_interface(self, get_config):
        """
        ``get_client_resource`` returns an object that provides ``IResource``.
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")
        config = get_config(nodedir, b"tub.port")
        self.assertThat(
            storage_server.get_client_resource(
                config,
                reactor=Clock(),
            ),
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
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")
        privatedir = tempdir.join(b"node", b"private")
        makedirs(privatedir)
        config = get_config(nodedir, b"tub.port")

        if servers_yaml is not None:
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

        return create_client_from_config(config)

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
            # Then generate build a function that will get us a Tahoe
            # configuration that includes at least that lease maintenance
            # configuration.
            lambda lease_maint_config: tahoe_configs(
                zkapauthz_v1_configuration=client_lease_maintenance_configurations(
                    just(lease_maint_config),
                ),
            ).map(
                # Then bundle up both pieces to pass to the function.  By
                # preserving the simple lease maintenance configuration and
                # making it available to the test, the test logic is much
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


def has_lease_maintenance_service():
    """
    Return a matcher for a Tahoe-LAFS client object that has a lease
    maintenance service.
    """
    # type: () -> Matcher
    return AfterPreprocessing(
        lambda client: client.getServiceNamed(SERVICE_NAME),
        Always(),
    )


def has_lease_maintenance_configuration(lease_maint_config):
    """
    Return a matcher for a Tahoe-LAFS client object that has a lease
    maintenance service with the given configuration.
    """
    # type: (_LeaseMaintenanceConfig) -> Matcher
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
        p = FilePath(self.useFixture(TempDir()).join(b"key"))
        p.setContent(key_bytes)
        key = load_signing_key(p)
        self.assertThat(key, IsInstance(SigningKey))
