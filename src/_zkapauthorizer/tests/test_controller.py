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

from __future__ import (
    absolute_import,
)

from json import (
    loads,
    dumps,
)
from functools import (
    partial,
)
from zope.interface import (
    implementer,
)
from testtools import (
    TestCase,
)
from testtools.content import (
    text_content,
)
from testtools.matchers import (
    Equals,
    MatchesAll,
    AllMatch,
    IsInstance,
    HasLength,
    AfterPreprocessing,
    MatchesStructure,
)
from testtools.twistedsupport import (
    succeeded,
    failed,
)

from hypothesis import (
    given,
)
from hypothesis.strategies import (
    integers,
    datetimes,
)
from twisted.python.url import (
    URL,
)
from twisted.internet.defer import (
    fail,
)
from twisted.web.iweb import (
    IAgent,
)
from twisted.web.resource import (
    ErrorPage,
    Resource,
)
from twisted.web.http import (
    UNSUPPORTED_MEDIA_TYPE,
    BAD_REQUEST,
)
from treq.testing import (
    StubTreq,
)

from privacypass import (
    SecurityException,
    PublicKey,
    BlindedToken,
    BatchDLEQProof,
    TokenPreimage,
    VerificationSignature,
    random_signing_key,
)

from ..controller import (
    IRedeemer,
    NonRedeemer,
    DummyRedeemer,
    DoubleSpendRedeemer,
    UnpaidRedeemer,
    RistrettoRedeemer,
    PaymentController,
    AlreadySpent,
    Unpaid,
)

from ..model import (
    UnblindedToken,
    Pending as model_Pending,
    DoubleSpend as model_DoubleSpend,
    Redeemed as model_Redeemed,
    Unpaid as model_Unpaid,
)

from .strategies import (
    tahoe_configs,
    vouchers,
    voucher_objects,
)
from .matchers import (
    Provides,
)
from .fixtures import (
    TemporaryVoucherStore,
)


class PaymentControllerTests(TestCase):
    """
    Tests for ``PaymentController``.
    """
    @given(tahoe_configs(), datetimes(), vouchers())
    def test_not_redeemed_while_redeeming(self, get_config, now, voucher):
        """
        A ``Voucher`` is not marked redeemed before ``IRedeemer.redeem``
        completes.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        controller = PaymentController(
            store,
            NonRedeemer(),
        )
        controller.redeem(voucher)

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher.state,
            Equals(model_Pending()),
        )

    @given(tahoe_configs(), datetimes(), vouchers())
    def test_redeemed_after_redeeming(self, get_config, now, voucher):
        """
        A ``Voucher`` is marked as redeemed after ``IRedeemer.redeem`` succeeds.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        controller = PaymentController(
            store,
            DummyRedeemer(),
        )
        controller.redeem(voucher)

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher.state,
            Equals(model_Redeemed(
                finished=now,
                token_count=100,
            )),
        )

    @given(tahoe_configs(), datetimes(), vouchers())
    def test_double_spent_after_double_spend(self, get_config, now, voucher):
        """
        A ``Voucher`` is marked as double-spent after ``IRedeemer.redeem`` fails
        with ``AlreadySpent``.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        controller = PaymentController(
            store,
            DoubleSpendRedeemer(),
        )
        controller.redeem(voucher)

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher,
            MatchesStructure(
                state=Equals(model_DoubleSpend(
                    finished=now,
                )),
            ),
        )

    @given(tahoe_configs(), datetimes(), vouchers())
    def test_redeem_pending_on_startup(self, get_config, now, voucher):
        """
        When ``PaymentController`` is created, any vouchers in the store in the
        pending state are redeemed.
        """
        store = self.useFixture(TemporaryVoucherStore(get_config, lambda: now)).store
        # Create the voucher state in the store with a redemption that will
        # certainly fail.
        unpaid_controller = PaymentController(
            store,
            UnpaidRedeemer(),
        )
        unpaid_controller.redeem(voucher)

        # Make sure we got where we wanted.
        self.assertThat(
            unpaid_controller.get_voucher(voucher).state,
            IsInstance(model_Unpaid),
        )

        # Create another controller with the same store.  It will see the
        # voucher state and attempt a redemption on its own.  It has I/O as an
        # `__init__` side-effect. :/
        success_controller = PaymentController(
            store,
            DummyRedeemer(),
        )

        self.assertThat(
            success_controller.get_voucher(voucher).state,
            IsInstance(model_Redeemed),
        )


NOWHERE = URL.from_text(u"https://127.0.0.1/")

class RistrettoRedeemerTests(TestCase):
    """
    Tests for ``RistrettoRedeemer``.
    """
    def test_interface(self):
        """
        An ``RistrettoRedeemer`` instance provides ``IRedeemer``.
        """
        redeemer = RistrettoRedeemer(stub_agent(), NOWHERE)
        self.assertThat(
            redeemer,
            Provides([IRedeemer]),
        )

    @given(voucher_objects(), integers(min_value=1, max_value=100))
    def test_good_ristretto_redemption(self, voucher, num_tokens):
        """
        If the issuer returns a successful result then
        ``RistrettoRedeemer.redeem`` returns a ``Deferred`` that fires with a
        list of ``UnblindedToken`` instances.
        """
        signing_key = random_signing_key()
        issuer = RistrettoRedemption(signing_key)
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, num_tokens)
        d = redeemer.redeem(
            voucher,
            random_tokens,
        )
        self.assertThat(
            d,
            succeeded(
                MatchesAll(
                    AllMatch(
                        IsInstance(UnblindedToken),
                    ),
                    HasLength(num_tokens),
                ),
            ),
        )

    @given(voucher_objects(), integers(min_value=1, max_value=100))
    def test_redemption_denied_alreadyspent(self, voucher, num_tokens):
        """
        If the issuer declines to allow the voucher to be redeemed and gives a
        reason that the voucher has already been spent, ``RistrettoRedeem``
        returns a ``Deferred`` that fires with a ``Failure`` wrapping
        ``AlreadySpent``.
        """
        issuer = AlreadySpentRedemption()
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, num_tokens)
        d = redeemer.redeem(
            voucher,
            random_tokens,
        )
        self.assertThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(AlreadySpent),
                ),
            ),
        )

    @given(voucher_objects(), integers(min_value=1, max_value=100))
    def test_redemption_denied_unpaid(self, voucher, num_tokens):
        """
        If the issuer declines to allow the voucher to be redeemed and gives a
        reason that the voucher has not been paid for, ``RistrettoRedeem``
        returns a ``Deferred`` that fires with a ``Failure`` wrapping
        ``Unpaid``.
        """
        issuer = UnpaidRedemption()
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, num_tokens)
        d = redeemer.redeem(
            voucher,
            random_tokens,
        )
        self.assertThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(Unpaid),
                ),
            ),
        )

    @given(voucher_objects(), integers(min_value=1, max_value=100))
    def test_bad_ristretto_redemption(self, voucher, num_tokens):
        """
        If the issuer returns a successful result with an invalid proof then
        ``RistrettoRedeemer.redeem`` returns a ``Deferred`` that fires with a
        ``Failure`` wrapping ``SecurityException``.
        """
        signing_key = random_signing_key()
        issuer = RistrettoRedemption(signing_key)

        # Make it lie about the public key it is using.  This causes the proof
        # to be invalid since it proves the signature was made with a
        # different key than reported in the response.
        issuer.public_key = PublicKey.from_signing_key(random_signing_key())

        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, num_tokens)
        d = redeemer.redeem(
            voucher,
            random_tokens,
        )
        self.addDetail(u"redeem Deferred", text_content(str(d)))
        self.assertThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(SecurityException),
                ),
            ),
        )

    @given(voucher_objects(), integers(min_value=1, max_value=100))
    def test_ristretto_pass_construction(self, voucher, num_tokens):
        """
        The passes constructed using unblinded tokens and messages pass the
        Ristretto verification check.
        """
        message = b"hello world"

        signing_key = random_signing_key()
        issuer = RistrettoRedemption(signing_key)
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)

        random_tokens = redeemer.random_tokens_for_voucher(voucher, num_tokens)
        d = redeemer.redeem(
            voucher,
            random_tokens,
        )
        def unblinded_tokens_to_passes(unblinded_tokens):
            passes = redeemer.tokens_to_passes(message, unblinded_tokens)
            return passes
        d.addCallback(unblinded_tokens_to_passes)

        self.assertThat(
            d,
            succeeded(
                AfterPreprocessing(
                    partial(ristretto_verify, signing_key, message),
                    Equals(True),
                ),
            ),
        )


def ristretto_verify(signing_key, message, marshaled_passes):
    """
    Verify that the given passes were generated in a process that involved a
    signature from the given signing key and using the given message.

    :param privacypass.SigningKey signing_key: A signing key which should have
        signed some random blinded tokens earlier in the lifecycle of the
        passes to verify.

    :param bytes message: Request binding data which is involved in the
        generation of the passes to verify.

    :param list[bytes] marshaled_passes: Token preimages and corresponding
        message signatures to verify.  Each element contains two
        space-separated base64 encoded values, the first representing the
        preimage and the second representing the signature.

    :return bool: ``True`` if and only if all of the passes represented by
        ``marshaled_passes`` pass the Ristretto-defined verification for an
        exchange using the given signing key and message.
    """
    def decode(marshaled_pass):
        t, s = marshaled_pass.split(u" ")
        return (
            TokenPreimage.decode_base64(t.encode("ascii")),
            VerificationSignature.decode_base64(s.encode("ascii")),
        )
    servers_passes = list(
        decode(marshaled_pass.text)
        for marshaled_pass
        in marshaled_passes
    )
    servers_unblinded_tokens = list(
        signing_key.rederive_unblinded_token(token_preimage)
        for (token_preimage, sig)
        in servers_passes
    )
    servers_verification_sigs = list(
        sig
        for (token_preimage, sig)
        in servers_passes
    )
    servers_verification_keys = list(
        unblinded_token.derive_verification_key_sha512()
        for unblinded_token
        in servers_unblinded_tokens
    )
    invalid_passes = list(
        key.invalid_sha512(
            sig,
            message,
        )
        for (key, sig)
        in zip(servers_verification_keys, servers_verification_sigs)
    )

    return not any(invalid_passes)


def treq_for_loopback_ristretto(local_issuer):
    """
    Create a ``treq``-alike which can dispatch to a local issuer.
    """
    v1 = Resource()
    v1.putChild(b"redeem", local_issuer)
    root = Resource()
    root.putChild(b"v1", v1)
    return StubTreq(root)


@implementer(IAgent)
class _StubAgent(object):
    def request(self, method, uri, headers=None, bodyProducer=None):
        return fail(Exception("It's only a model."))


def stub_agent():
    return _StubAgent()


class AlreadySpentRedemption(Resource):
    """
    An ``AlreadySpentRedemption`` simulates the Ristretto redemption server
    but always refuses to allow vouchers to be redeemed and reports an error
    that the voucher has already been redeemed.
    """
    def render_POST(self, request):
        if request.requestHeaders.getRawHeaders(b"content-type") != ["application/json"]:
            return bad_content_type(request)

        return bad_request(request, {u"success": False, u"reason": u"double-spend"})


class UnpaidRedemption(Resource):
    """
    An ``UnpaidRedemption`` simulates the Ristretto redemption server but
    always refuses to allow vouchers to be redeemed and reports an error that
    the voucher has not been paid for.
    """
    def render_POST(self, request):
        if request.requestHeaders.getRawHeaders(b"content-type") != ["application/json"]:
            return bad_content_type(request)

        return bad_request(request, {u"success": False, u"reason": u"unpaid"})


class RistrettoRedemption(Resource):
    def __init__(self, signing_key):
        Resource.__init__(self)
        self.signing_key = signing_key
        self.public_key = PublicKey.from_signing_key(signing_key)

    def render_POST(self, request):
        if request.requestHeaders.getRawHeaders(b"content-type") != ["application/json"]:
            return bad_content_type(request)

        request_body = loads(request.content.read())
        marshaled_blinded_tokens = request_body[u"redeemTokens"]
        servers_blinded_tokens = list(
            BlindedToken.decode_base64(marshaled_blinded_token.encode("ascii"))
            for marshaled_blinded_token
            in marshaled_blinded_tokens
        )
        servers_signed_tokens = list(
            self.signing_key.sign(blinded_token)
            for blinded_token
            in servers_blinded_tokens
        )
        marshaled_signed_tokens = list(
            signed_token.encode_base64()
            for signed_token
            in servers_signed_tokens
        )
        servers_proof = BatchDLEQProof.create(
            self.signing_key,
            servers_blinded_tokens,
            servers_signed_tokens,
        )
        try:
            marshaled_proof = servers_proof.encode_base64()
        finally:
            servers_proof.destroy()

        return dumps({
            u"success": True,
            u"public-key": self.public_key.encode_base64(),
            u"signatures": marshaled_signed_tokens,
            u"proof": marshaled_proof,
        })


def bad_request(request, body_object):
    request.setResponseCode(BAD_REQUEST)
    request.setHeader(b"content-type", b"application/json")
    request.write(dumps(body_object))
    return b""


def bad_content_type(request):
    return ErrorPage(
        UNSUPPORTED_MEDIA_TYPE,
        b"Unsupported media type",
        b"Unsupported media type",
    ).render(request)
