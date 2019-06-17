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

from zope.interface.verify import (
    verifyObject,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    Contains,
    AfterPreprocessing,
)
from testtools.twistedsupport import (
    succeeded,
)

from hypothesis import (
    given,
)

from foolscap.ipb import (
    IReferenceable,
    IRemotelyCallable,
)

from allmydata.interfaces import (
    IFoolscapStoragePlugin,
    IAnnounceableStorageServer,
)

from twisted.plugin import (
    getPlugins,
)
from twisted.plugins.secureaccesstokenauthorizer import (
    storage_server,
)

from .strategies import (
    configurations,
)
from .matchers import (
    Provides,
)

def get_anonymous_storage_server():
    return None


class PluginTests(TestCase):
    """
    Tests for ``twisted.plugins.secureaccesstokenauthorizer.storage_server``.
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
        verifyObject(IFoolscapStoragePlugin, storage_server)


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
        # XXX It's not clear what the actual Foolscap-imposed requirements on
        # this object should be.  Maybe the two above-mentioned interfaces are
        # important ... or maybe not?

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
