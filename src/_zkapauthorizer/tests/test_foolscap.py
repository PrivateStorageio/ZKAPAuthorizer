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
Tests for Foolscap-related test helpers.
"""

from __future__ import (
    absolute_import,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    MatchesAll,
    AfterPreprocessing,
    Always,
    IsInstance,
)

from foolscap.furl import (
    decode_furl,
)
from foolscap.pb import (
    Tub,
)
from foolscap.referenceable import (
    RemoteReferenceTracker,
    RemoteReferenceOnly,
)

from hypothesis import (
    given,
)
from hypothesis.strategies import (
    one_of,
    just,
)

from .foolscap import (
    RIStub,
    LocalRemote,
    DummyReferenceable,
)

def remote_reference():
    tub = Tub()
    tub.setLocation("127.0.0.1:12345")
    url = tub.buildURL(b"efgh")

    # Ugh ugh ugh.  Skip over the extra correctness checking in
    # RemoteReferenceTracker.__init__ that requires having a broker by passing
    # the url as None and setting it after.
    tracker = RemoteReferenceTracker(None, None, None, RIStub)
    tracker.url = url

    ref = RemoteReferenceOnly(tracker)
    return ref


class LocalRemoteTests(TestCase):
    """
    Tests for the ``LocalRemote`` test double.
    """
    @given(
        ref=one_of(
            just(remote_reference()),
            just(LocalRemote(DummyReferenceable(RIStub))),
        ),
    )
    def test_tracker_url(self, ref):
        """
        The URL of a remote reference can be retrieved using the tracker
        attribute.
        """
        self.assertThat(
            ref.tracker.getURL(),
            MatchesAll(
                IsInstance(bytes),
                AfterPreprocessing(
                    decode_furl,
                    Always(),
                ),
            ),
        )
