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

from fixtures import Fixture
from foolscap.api import Any, RemoteInterface, Violation
from foolscap.furl import decode_furl
from foolscap.pb import Tub
from foolscap.referenceable import RemoteReferenceOnly, RemoteReferenceTracker
from hypothesis import given
from hypothesis.strategies import just, one_of
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    Equals,
    IsInstance,
    MatchesAll,
)
from testtools.twistedsupport import failed, succeeded
from twisted.internet.defer import inlineCallbacks
from twisted.trial.unittest import TestCase as TrialTestCase

from ..foolscap import ShareStat
from .foolscap import BrokenCopyable, DummyReferenceable, Echoer, LocalRemote, RIStub


class IHasSchema(RemoteInterface):
    def method(arg=int):
        return bytes

    def good_method(arg=int):
        return None

    def whatever_method(arg=Any()):
        return Any()


def remote_reference():
    tub = Tub()
    tub.setLocation("127.0.0.1:12345")
    url = tub.buildURL("efgh")

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
                IsInstance(str),
                AfterPreprocessing(
                    decode_furl,
                    Always(),
                ),
            ),
        )

    def test_arg_schema(self):
        """
        ``LocalRemote.callRemote`` returns a ``Deferred`` that fails with a
        ``Violation`` if an parameter receives an argument which doesn't
        conform to its schema.
        """
        ref = LocalRemote(DummyReferenceable(IHasSchema))
        self.assertThat(
            ref.callRemote("method", None),
            failed(
                AfterPreprocessing(
                    lambda f: f.type,
                    Equals(Violation),
                ),
            ),
        )

    def test_result_schema(self):
        """
        ``LocalRemote.callRemote`` returns a ``Deferred`` that fails with a
        ``Violation`` if a method returns an object which doesn't conform to
        the method's result schema.
        """
        ref = LocalRemote(DummyReferenceable(IHasSchema))
        self.assertThat(
            ref.callRemote("method", 0),
            failed(
                AfterPreprocessing(
                    lambda f: f.type,
                    Equals(Violation),
                ),
            ),
        )

    def test_successful_method(self):
        """
        ``LocalRemote.callRemote`` returns a ``Deferred`` that fires with the
        remote method's result if the arguments and result conform to their
        respective schemas.
        """
        ref = LocalRemote(DummyReferenceable(IHasSchema))
        self.assertThat(
            ref.callRemote("good_method", 0),
            succeeded(Equals(None)),
        )

    def test_argument_serialization_failure(self):
        """
        ``LocalRemote.callRemote`` returns a ``Deferred`` that fires with a
        failure if an argument cannot be serialized.
        """
        ref = LocalRemote(DummyReferenceable(IHasSchema))
        self.assertThat(
            ref.callRemote("whatever_method", BrokenCopyable()),
            failed(Always()),
        )

    def test_result_serialization_failure(self):
        """
        ``LocalRemote.callRemote`` returns a ``Deferred`` that fires with a
        failure if the method's result cannot be serialized.
        """

        class BrokenResultReferenceable(DummyReferenceable):
            def doRemoteCall(self, *a, **kw):
                return BrokenCopyable()

        ref = LocalRemote(BrokenResultReferenceable(IHasSchema))
        self.assertThat(
            ref.callRemote("whatever_method", None),
            failed(Always()),
        )


class EchoerFixture(Fixture):
    def __init__(self, reactor, tub_path):
        self.reactor = reactor
        self.tub = Tub()
        self.tub.setLocation(b"tcp:0")

    def _setUp(self):
        self.tub.startService()
        self.furl = self.tub.registerReference(Echoer())

    def _cleanUp(self):
        return self.tub.stopService()


class SerializationTests(TrialTestCase):
    """
    Tests for the serialization of types used in the Foolscap API.
    """

    def test_sharestat(self):
        """
        A ``ShareStat`` instance can be sent as an argument to and received in a
        response from a Foolscap remote method call.
        """
        return self._roundtrip_test(ShareStat(1, 2))

    @inlineCallbacks
    def _roundtrip_test(self, obj):
        """
        Send ``obj`` over Foolscap and receive it back again, equal to itself.
        """
        # Foolscap Tub implementation just uses the global reactor...
        from twisted.internet import reactor

        # So sad.  No Deferred support in testtools.TestCase or
        # fixture.Fixture, no fixture support in
        # twisted.trial.unittest.TestCase.
        fx = EchoerFixture(reactor, self.mktemp())
        fx.setUp()
        self.addCleanup(fx._cleanUp)
        echoer = yield fx.tub.getReference(fx.furl)
        received = yield echoer.callRemote("echo", obj)
        self.assertEqual(obj, received)
