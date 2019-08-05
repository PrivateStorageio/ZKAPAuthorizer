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
    Matcher,
    Mismatch,
    ContainsDict,
    Always,
)

@attr.s
class Provides(object):
    """
    Match objects that provide all of a list of Zope Interface interfaces.
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


def matches_version_dictionary():
    """
    Match the dictionary returned by Tahoe-LAFS'
    ``RIStorageServer.get_version`` which is also the dictionary returned by
    our own ``RITokenAuthorizedStorageServer.get_version``.
    """
    return ContainsDict({
        # It has these two top-level keys, at least.  Try not to be too
        # fragile by asserting much more than that they are present.
        b'application-version': Always(),
        b'http://allmydata.org/tahoe/protocols/storage/v1': Always(),
    })



def returns(matcher):
    """
    Matches a no-argument callable that returns a value matched by the given
    matcher.
    """
    return _Returns(matcher)



class _Returns(Matcher):
    def __init__(self, result_matcher):
        self.result_matcher = result_matcher


    def match(self, matchee):
        return self.result_matcher.match(matchee())


    def __str__(self):
        return "Returns({})".format(self.result_matcher)
