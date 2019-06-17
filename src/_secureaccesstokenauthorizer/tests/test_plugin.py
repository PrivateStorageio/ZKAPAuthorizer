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
)

from allmydata.interfaces import (
    IFoolscapStoragePlugin,
)

from twisted.plugin import (
    getPlugins,
)
from twisted.plugins.secureaccesstokenauthorizer import (
    storage_server,
)

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
