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
Testtools matchers useful for the test suite.
"""

import attr

from testtools.matchers import (
    Mismatch,
)

@attr.s
class Provides(object):
    """
    Match objects that provide one or more Zope Interface interfaces.
    """
    interfaces = attr.ib()

    def match(self, obj):
        missing = set()
        for iface in self.interfaces:
            if not iface.providedBy(obj):
                missing.add(iface)
        if missing:
            return Mismatch("{} does not provide expected {}".format(
                obj, ", ".join(str(iface) for iface in missing),
            ))
