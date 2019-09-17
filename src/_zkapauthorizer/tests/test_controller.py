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
Tests for ``_zkapauthorizer.controller``.
"""

from json import (
    loads,
    dumps,
)
from zope.interface import (
    implementer,
)
from testtools import (
    TestCase,
)
from testtools.matchers import (
    Equals,
    MatchesAll,
    AllMatch,
    IsInstance,
    HasLength,
)
from testtools.twistedsupport import (
    succeeded,
)

from fixtures import (
    TempDir,
)

from hypothesis import (
    given,
)
from hypothesis.strategies import (
    integers,
)
from twisted.internet.defer import (
    fail,
)
from twisted.web.iweb import (
    IAgent,
)
from twisted.web.resource import (
    Resource,
)
from treq.testing import (
    RequestTraversalAgent,
)
from ..controller import (
    IRedeemer,
    NonRedeemer,
    DummyRedeemer,
    RistrettoRedeemer,
    PaymentController,
)

from ..model import (
    memory_connect,
    VoucherStore,
    Pass,
)

from .strategies import (
    tahoe_configs,
    vouchers,
)
from .matchers import (
    Provides,
)

class PaymentControllerTests(TestCase):
    """
    Tests for ``PaymentController``.
    """
    @given(tahoe_configs(), vouchers())
    def test_not_redeemed_while_redeeming(self, get_config, voucher):
        """
        A ``Voucher`` is not marked redeemed before ``IRedeemer.redeem``
        completes.
        """
        tempdir = self.useFixture(TempDir())
        store = VoucherStore.from_node_config(
            get_config(
                tempdir.join(b"node"),
                b"tub.port",
            ),
            connect=memory_connect,
        )
        controller = PaymentController(
            store,
            NonRedeemer(),
        )
        controller.redeem(voucher)

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher.redeemed,
            Equals(False),
        )

    @given(tahoe_configs(), vouchers())
    def test_redeemed_after_redeeming(self, get_config, voucher):
        tempdir = self.useFixture(TempDir())
        store = VoucherStore.from_node_config(
            get_config(
                tempdir.join(b"node"),
                b"tub.port",
            ),
            connect=memory_connect,
        )
        controller = PaymentController(
            store,
            DummyRedeemer(),
        )
        controller.redeem(voucher)

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher.redeemed,
            Equals(True),
        )


class RistrettoRedeemerTests(TestCase):
    """
    Tests for ``RistrettoRedeemer``.
    """
    def test_interface(self):
        """
        An ``RistrettoRedeemer`` instance provides ``IRedeemer``.
        """
        redeemer = RistrettoRedeemer(stub_agent())
        self.assertThat(
            redeemer,
            Provides([IRedeemer]),
        )

    @given(vouchers(), integers(min_value=1, max_value=100))
    def test_redemption(self, voucher, num_tokens):
        """
        ``RistrettoRedeemer.redeem`` returns a ``Deferred`` that fires with a list
        of ``Pass`` instances.
        """
        public_key = u"pub foo-bar"
        signatures = list(u"sig-{}".format(n) for n in range(num_tokens))
        proof = u"proof bar-foo"

        issuer = SuccessfulRedemption(public_key, signatures, proof)
        agent = agent_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(agent)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, num_tokens)
        # The redeemer gives back the requested number of tokens.
        self.expectThat(
            len(random_tokens),
            Equals(num_tokens),
        )
        d = redeemer.redeem(
            voucher,
            random_tokens,
        )
        # Perform some very basic checks on the results.  We won't verify the
        # crypto here since we don't have a real Ristretto server.  Such
        # checks would fail.  Some integration tests will verify that part of
        # things.
        self.assertThat(
            d,
            succeeded(
                MatchesAll(
                    AllMatch(
                        IsInstance(Pass),
                    ),
                    HasLength(num_tokens),
                ),
            ),
        )


def agent_for_loopback_ristretto(local_issuer):
    """
    Create an ``IAgent`` which can dispatch to a local issuer.
    """
    v1 = Resource()
    v1.putChild(b"redeem", local_issuer)
    root = Resource()
    root.putChild(b"v1", v1)
    return RequestTraversalAgent(root)


class SuccessfulRedemption(Resource):
    def __init__(self, public_key, signatures, proof):
        Resource.__init__(self)
        self.public_key = public_key
        self.signatures = signatures
        self.proof = proof
        self.redemptions = []

    def render_POST(self, request):
        request_body = loads(request.content.read())
        voucher = request_body[u"redeemVoucher"]
        tokens = request_body[u"redeemTokens"]
        self.redemptions.append((voucher, tokens))
        return dumps({
            u"success": True,
            u"public-key": self.public_key,
            u"signatures": self.signatures,
            u"proof": self.proof,
        })


@implementer(IAgent)
class _StubAgent(object):
    def request(self, method, uri, headers=None, bodyProducer=None):
        return fail(Exception("It's only a model."))


def stub_agent():
    return _StubAgent()
