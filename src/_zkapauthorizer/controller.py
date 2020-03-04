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
This module implements controllers (in the MVC sense) for the web interface
for the client side of the storage plugin.
"""

from sys import (
    exc_info,
)
from operator import (
    setitem,
    delitem,
)
from functools import (
    partial,
)
from json import (
    dumps,
)
from datetime import (
    timedelta,
)
from base64 import (
    b64encode,
    b64decode,
)
import attr

from zope.interface import (
    Interface,
    implementer,
)

from twisted.python.reflect import (
    namedAny,
)
from twisted.logger import (
    Logger,
)
from twisted.python.url import (
    URL,
)
from twisted.internet.defer import (
    Deferred,
    succeed,
    fail,
    inlineCallbacks,
    returnValue,
)
from twisted.internet.task import (
    LoopingCall,
)
from twisted.web.client import (
    Agent,
)
from treq import (
    json_content,
)
from treq.client import (
    HTTPClient,
)

import privacypass

from ._base64 import (
    urlsafe_b64decode,
)

from .model import (
    RandomToken,
    UnblindedToken,
    Voucher,
    Pass,
    Pending as model_Pending,
    Unpaid as model_Unpaid,
    Redeeming as model_Redeeming,
    Error as model_Error,
)

# The number of tokens to submit with a voucher redemption.
NUM_TOKENS = 100

RETRY_INTERVAL = timedelta(minutes=3)

class AlreadySpent(Exception):
    """
    An attempt was made to redeem a voucher which has already been redeemed.
    The redemption cannot succeed and should not be retried automatically.
    """


class Unpaid(Exception):
    """
    An attempt was made to redeem a voucher which has not yet been paid for.

    The redemption attempt may be automatically retried at some point.
    """


class IRedeemer(Interface):
    """
    An ``IRedeemer`` can exchange a voucher for one or more passes.
    """
    def random_tokens_for_voucher(voucher, count):
        """
        Generate a number of random tokens to use in the redemption process for
        the given voucher.

        :param Voucher voucher: The voucher the tokens will be associated
            with.

        :param int count: The number of random tokens to generate.

        :return list[RandomToken]: The generated tokens.  Random tokens must
            be unique over the lifetime of the Tahoe-LAFS node where this
            plugin is being used but the same tokens *may* be generated for
            the same voucher.  The tokens must be kept secret to preserve the
            anonymity property of the system.
        """

    def redeem(voucher, random_tokens):
        """
        Redeem a voucher for unblinded tokens which can be used to construct
        passes.

        Implementations of this method do not need to be fault tolerant.  If a
        redemption attempt is interrupted before it completes, it is the
        caller's responsibility to call this method again with the same
        arguments.

        :param Voucher voucher: The voucher to redeem.

        :param list[RandomToken] random_tokens: The random tokens to use in
            the redemption process.

        :return: A ``Deferred`` which fires with a list of ``UnblindedToken``
            instances on successful redemption or which fails with any error
            to allow a retry to be made at some future point.  It may also
            fail with an ``AlreadySpent`` error to indicate the redemption
            server considers the voucher to have been redeemed already and
            will not allow it to be redeemed.
        """

    def tokens_to_passes(message, unblinded_tokens):
        """
        Construct passes from unblinded tokens which are suitable for use with a
        given message.

        :param bytes message: A valid utf-8-encoded byte sequence which serves
            to protect the resulting passes from replay usage.  It is
            preferable if every use of passes is associated with a unique
            message.

        :param list[UnblindedToken] unblinded_tokens: Unblinded tokens,
            previously returned by a call to this implementation's ``redeem``
            method.

        :return list[Pass]: Passes constructed from the message and unblinded
            tokens.  There is one pass in the resulting list for each unblinded
            token in ``unblinded_tokens``.
        """


@implementer(IRedeemer)
class NonRedeemer(object):
    """
    A ``NonRedeemer`` never tries to redeem vouchers for ZKAPs.
    """
    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        return cls()

    def random_tokens_for_voucher(self, voucher, count):
        return dummy_random_tokens(voucher, count)

    def redeem(self, voucher, random_tokens):
        # Don't try to redeem them.
        return Deferred()

    def tokens_to_passes(self, message, unblinded_tokens):
        raise Exception(
            "Cannot be called because no unblinded tokens are ever returned."
        )


@implementer(IRedeemer)
@attr.s(frozen=True)
class ErrorRedeemer(object):
    """
    An ``ErrorRedeemer`` immediately locally fails voucher redemption with a
    configured error.
    """
    details = attr.ib(validator=attr.validators.instance_of(unicode))

    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        details = node_config.get_config(
            section=section_name,
            option=u"details",
        ).decode("ascii")
        return cls(details)

    def random_tokens_for_voucher(self, voucher, count):
        return dummy_random_tokens(voucher, count)

    def redeem(self, voucher, random_tokens):
        return fail(Exception(self.details))

    def tokens_to_passes(self, message, unblinded_tokens):
        raise Exception(
            "Cannot be called because no unblinded tokens are ever returned."
        )


@implementer(IRedeemer)
@attr.s
class DoubleSpendRedeemer(object):
    """
    A ``DoubleSpendRedeemer`` pretends to try to redeem vouchers for ZKAPs but
    always fails with an error indicating the voucher has already been spent.
    """
    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        return cls()

    def random_tokens_for_voucher(self, voucher, count):
        return dummy_random_tokens(voucher, count)

    def redeem(self, voucher, random_tokens):
        return fail(AlreadySpent(voucher))


@implementer(IRedeemer)
@attr.s
class UnpaidRedeemer(object):
    """
    An ``UnpaidRedeemer`` pretends to try to redeem vouchers for ZKAPs but
    always fails with an error indicating the voucher has not been paid for.
    """
    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        return cls()

    def random_tokens_for_voucher(self, voucher, count):
        return dummy_random_tokens(voucher, count)

    def redeem(self, voucher, random_tokens):
        return fail(Unpaid(voucher))


def dummy_random_tokens(voucher, count):
    v = urlsafe_b64decode(voucher.number.encode("ascii"))
    def dummy_random_token(n):
        return RandomToken(
            # Padding is 96 (random token length) - 32 (decoded voucher
            # length)
            b64encode(
                v + u"{:0>64}".format(n).encode("ascii"),
            ).decode("ascii"),
        )
    return list(
        dummy_random_token(n)
        for n
        in range(count)
    )


@implementer(IRedeemer)
@attr.s
class DummyRedeemer(object):
    """
    A ``DummyRedeemer`` pretends to redeem vouchers for ZKAPs.  Instead of
    really redeeming them, it makes up some fake ZKAPs and pretends those are
    the result.
    """
    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        return cls()

    def random_tokens_for_voucher(self, voucher, count):
        """
        Generate some number of random tokens to submit along with a voucher for
        redemption.
        """
        return dummy_random_tokens(voucher, count)

    def redeem(self, voucher, random_tokens):
        """
        :return: An already-fired ``Deferred`` that has a list of
          ``UnblindedToken`` instances wrapping meaningless values.
        """
        def dummy_unblinded_token(random_token):
            random_value = b64decode(random_token.token_value.encode("ascii"))
            unblinded_value = random_value + b"x" * (96 - len(random_value))
            return UnblindedToken(b64encode(unblinded_value).decode("ascii"))
        return succeed(
            list(
                dummy_unblinded_token(token)
                for token
                in random_tokens
            ),
        )

    def tokens_to_passes(self, message, unblinded_tokens):
        def token_to_pass(token):
            # Smear the unblinded token value across the two new values we
            # need.
            bs = b64decode(token.unblinded_token.encode("ascii"))
            preimage = bs[:48] + b"x" * 16
            signature = bs[48:] + b"y" * 16
            return Pass(
                b64encode(preimage).decode("ascii"),
                b64encode(signature).decode("ascii"),
            )
        return list(
            token_to_pass(token)
            for token
            in unblinded_tokens
        )


class IssuerConfigurationMismatch(Exception):
    """
    The Ristretto issuer address in the local client configuration does not
    match the Ristretto issuer address received in a storage server
    announcement.

    If these values do not match then there is no reason to expect that ZKAPs
    will be accepted by the storage server because ZKAPs are bound to the
    issuer's signing key.

    This mismatch must be corrected before the storage server can be used.
    Either the storage server needs to be reconfigured to respect the
    authority of a different issuer (the same one the client is configured to
    use), the client needs to select a different storage server to talk to, or
    the client needs to be reconfigured to respect the authority of a
    different issuer (the same one the storage server is announcing).

    Note that issued ZKAPs cannot be exchanged between issues except through
    some ad hoc, out-of-band means.  That is, if the client already has some
    ZKAPs and chooses to change its configured issuer address, those existing
    ZKAPs will not be usable and new ones must be obtained.
    """
    def __str__(self):
        return "Announced issuer ({}) disagrees with configured issuer ({}).".format(self.args)


@implementer(IRedeemer)
@attr.s
class RistrettoRedeemer(object):
    """
    An ``IRedeemer`` which speaks the Ristretto-flavored PrivacyPass protocol
    described at
    https://docs.rs/challenge-bypass-ristretto/1.0.0-pre.0/challenge_bypass_ristretto/#cryptographic-protocol

    :ivar treq.client.HTTPClient _treq: An HTTP client to use to make calls to
        the issuer.

    :ivar URL _api_root: The root of the issuer HTTP API.
    """
    _log = Logger()

    _treq = attr.ib()
    _api_root = attr.ib(validator=attr.validators.instance_of(URL))

    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        configured_issuer = node_config.get_config(
            section=section_name,
            option=u"ristretto-issuer-root-url",
        ).decode("ascii")
        if announcement is not None:
            # Don't let us talk to a storage server that has a different idea
            # about who issues ZKAPs.  We should lift this limitation (that is, we
            # should support as many different issuers as the user likes) in the
            # future but doing so requires changing how the web interface works
            # and possibly also the interface for voucher submission.
            #
            # If we aren't given an announcement then we're not being used in
            # the context of a specific storage server so the check is
            # unnecessary and impossible.
            announced_issuer = announcement[u"ristretto-issuer-root-url"]
            if announced_issuer != configured_issuer:
                raise IssuerConfigurationMismatch(announced_issuer, configured_issuer)

        return cls(
            HTTPClient(Agent(reactor)),
            URL.from_text(configured_issuer),
        )

    def random_tokens_for_voucher(self, voucher, count):
        return list(
            RandomToken(privacypass.RandomToken.create().encode_base64().decode("ascii"))
            for n
            in range(count)
        )

    @inlineCallbacks
    def redeem(self, voucher, encoded_random_tokens):
        random_tokens = list(
            privacypass.RandomToken.decode_base64(token.token_value.encode("ascii"))
            for token
            in encoded_random_tokens
        )
        blinded_tokens = list(token.blind() for token in random_tokens)
        response = yield self._treq.post(
            self._api_root.child(u"v1", u"redeem").to_text(),
            dumps({
                u"redeemVoucher": voucher.number,
                u"redeemTokens": list(
                    token.encode_base64()
                    for token
                    in blinded_tokens
                ),
            }),
            headers={b"content-type": b"application/json"},
        )
        try:
            result = yield json_content(response)
        except ValueError:
            self._log.failure("Parsing redeem response failed", response=response)
            raise

        success = result.get(u"success", False)
        if not success:
            reason = result.get(u"reason", None)
            if reason == u"double-spend":
                raise AlreadySpent(voucher)
            elif reason == u"unpaid":
                raise Unpaid(voucher)

        self._log.info("Redeemed: {public-key} {proof} {signatures}", **result)

        marshaled_signed_tokens = result[u"signatures"]
        marshaled_proof = result[u"proof"]
        marshaled_public_key = result[u"public-key"]

        public_key = privacypass.PublicKey.decode_base64(
            marshaled_public_key.encode("ascii"),
        )
        clients_signed_tokens = list(
            privacypass.SignedToken.decode_base64(
                marshaled_signed_token.encode("ascii"),
            )
            for marshaled_signed_token
            in marshaled_signed_tokens
        )
        clients_proof = privacypass.BatchDLEQProof.decode_base64(
            marshaled_proof.encode("ascii"),
        )
        clients_unblinded_tokens = clients_proof.invalid_or_unblind(
            random_tokens,
            blinded_tokens,
            clients_signed_tokens,
            public_key,
        )
        returnValue(list(
            UnblindedToken(token.encode_base64().decode("ascii"))
            for token
            in clients_unblinded_tokens
        ))

    def tokens_to_passes(self, message, unblinded_tokens):
        assert isinstance(message, bytes)
        assert isinstance(unblinded_tokens, list)
        assert all(isinstance(element, UnblindedToken) for element in unblinded_tokens)
        unblinded_tokens = list(
            privacypass.UnblindedToken.decode_base64(token.unblinded_token.encode("ascii"))
            for token
            in unblinded_tokens
        )
        clients_verification_keys = list(
            token.derive_verification_key_sha512()
            for token
            in unblinded_tokens
        )
        clients_signatures = list(
            verification_key.sign_sha512(message)
            for verification_key
            in clients_verification_keys
        )
        clients_preimages = list(
            token.preimage()
            for token
            in unblinded_tokens
        )
        passes = list(
            Pass(
                preimage.encode_base64().decode("ascii"),
                signature.encode_base64().decode("ascii"),
            )
            for (preimage, signature)
            in zip(clients_preimages, clients_signatures)
        )
        return passes


@attr.s
class PaymentController(object):
    """
    The ``PaymentController`` coordinates the process of turning a voucher
    into a collection of ZKAPs:

      1. A voucher to be consumed is handed to the controller.  Once a voucher
         is handed over to the controller the controller takes all
         responsibility for it.

      2. The controller tells the data store to remember the voucher.  The
         data store provides durability for the voucher which represents an
         investment (ie, a purchase) on the part of the client.

      3. The controller hands the voucher and some random tokens to a redeemer.
         In the future, this step will need to be retried in the case of failures.

      4. When the voucher has been redeemed for unblinded tokens (inputs to
         pass construction), the controller hands them to the data store with
         the voucher.  The data store marks the voucher as redeemed and stores
         the unblinded tokens for use by the storage client.

    :ivar dict[unicode, datetime] _active: A mapping from voucher identifiers
        which currently have redemption attempts in progress to timestamps
        when the attempt began.

    :ivar dict[unicode, datetime] _error: A mapping from voucher identifiers
        which have recently failed with an unrecognized, transient error.

    :ivar dict[unicode, datetime] _unpaid: A mapping from voucher identifiers
        which have recently failed a redemption attempt due to an unpaid
        response from the redemption server to timestamps when the failure was
        observed.
    """
    _log = Logger()

    store = attr.ib()
    redeemer = attr.ib()

    _clock = attr.ib(
        default=attr.Factory(partial(namedAny, "twisted.internet.reactor")),
    )

    _error = attr.ib(default=attr.Factory(dict))
    _unpaid = attr.ib(default=attr.Factory(dict))
    _active = attr.ib(default=attr.Factory(dict))

    def __attrs_post_init__(self):
        """
        Check the voucher store for any vouchers in need of redemption.

        This is an initialization-time hook called by attrs.
        """
        self._check_pending_vouchers()
        # Also start a time-based polling loop to retry redemption of vouchers
        # in retryable error states.
        self._schedule_retries()

    def _schedule_retries(self):
        # TODO: should not eagerly schedule calls.  If there are no vouchers
        # in an error state we shouldn't wake up at all.
        #
        # TODO: should schedule retries on a bounded exponential backoff
        # instead, perhaps on a per-voucher basis.
        self._retry_task = LoopingCall(self._retry_redemption)
        self._retry_task.clock = self._clock
        self._retry_task.start(
            RETRY_INTERVAL.total_seconds(),
            now=False,
        )

    def _retry_redemption(self):
        for voucher in self._error.keys() + self._unpaid.keys():
            if voucher in self._active:
                continue
            if self.get_voucher(voucher).state.should_start_redemption():
                self.redeem(voucher)

    def _check_pending_vouchers(self):
        """
        Find vouchers in the voucher store that need to be redeemed and try to
        redeem them.
        """
        vouchers = self.store.list()
        for voucher in vouchers:
            if voucher.state.should_start_redemption():
                self._log.info(
                    "Controller found voucher ({voucher}) at startup that needs redemption.",
                    voucher=voucher.number,
                )
                self.redeem(voucher.number)
            else:
                self._log.info(
                    "Controller found voucher ({voucher}) at startup that does not need redemption.",
                    voucher=voucher.number,
                )

    def _perform_redeem(self, voucher, random_tokens):
        """
        Use the redeemer to redeem the given voucher and random tokens.

        This will not persist the voucher or random tokens but it will persist
        the result.
        """
        # Ask the redeemer to do the real task of redemption.
        self._log.info("Redeeming random tokens for a voucher ({voucher}).", voucher=voucher)
        d = bracket(
            lambda: setitem(self._active, voucher, self.store.now()),
            lambda: delitem(self._active, voucher),
            lambda: self.redeemer.redeem(Voucher(voucher), random_tokens),
        )
        d.addCallbacks(
            partial(self._redeemSuccess, voucher),
            partial(self._redeemFailure, voucher),
        )
        d.addErrback(partial(self._finalRedeemError, voucher))
        return d

    def _get_random_tokens_for_voucher(self, voucher, num_tokens):
        """
        Generate or load random tokens for a redemption attempt of a voucher.
        """
        self._log.info("Generating random tokens for a voucher ({voucher}).", voucher=voucher)
        tokens = self.redeemer.random_tokens_for_voucher(Voucher(voucher), num_tokens)

        self._log.info("Persistenting random tokens for a voucher ({voucher}).", voucher=voucher)
        self.store.add(voucher, tokens)

        # XXX If the voucher is already in the store then the tokens passed to
        # `add` are dropped and we need to get the tokens already persisted in
        # the store.  add should probably return them so we can use them.  Or
        # maybe we should pass the generator in so it can be called only if
        # necessary.
        return tokens

    def redeem(self, voucher, num_tokens=None):
        """
        :param unicode voucher: A voucher to redeem.

        :param int num_tokens: A number of tokens to redeem.
        """
        # Pre-generate the random tokens to use when redeeming the voucher.
        # These are persisted with the voucher so the redemption can be made
        # idempotent.  We don't want to lose the value if we fail after the
        # server deems the voucher redeemed but before we persist the result.
        # With a stable set of tokens, we can re-submit them and the server
        # can re-sign them without fear of issuing excess passes.  Whether the
        # server signs a given set of random tokens once or many times, the
        # number of passes that can be constructed is still only the size of
        # the set of random tokens.
        if num_tokens is None:
            num_tokens = NUM_TOKENS
        tokens = self._get_random_tokens_for_voucher(voucher, num_tokens)
        return self._perform_redeem(voucher, tokens)

    def _redeemSuccess(self, voucher, unblinded_tokens):
        """
        Update the database state to reflect that a voucher was redeemed and to
        store the resulting unblinded tokens (which can be used to construct
        passes later).
        """
        self._log.info("Inserting redeemed unblinded tokens for a voucher ({voucher}).", voucher=voucher)
        self.store.insert_unblinded_tokens_for_voucher(voucher, unblinded_tokens)

    def _redeemFailure(self, voucher, reason):
        if reason.check(AlreadySpent):
            self._log.error(
                "Voucher {voucher} reported as already spent during redemption.",
                voucher=voucher,
            )
            self.store.mark_voucher_double_spent(voucher)
        elif reason.check(Unpaid):
            self._log.error(
                "Voucher {voucher} reported as not paid for during redemption.",
                voucher=voucher,
            )
            self._unpaid[voucher] = self.store.now()
        else:
            self._log.error(
                "Redeeming random tokens for a voucher ({voucher}) failed: {reason}",
                reason=reason,
                voucher=voucher,
            )
            self._error[voucher] = model_Error(
                finished=self.store.now(),
                details=reason.getErrorMessage().decode("utf-8", "replace"),
            )
        return None

    def _finalRedeemError(self, voucher, reason):
        self._log.failure("Redeeming random tokens for a voucher ({voucher}) encountered error.", reason, voucher=voucher)
        return None

    def get_voucher(self, number):
        return self.incorporate_transient_state(
            self.store.get(number),
        )

    def incorporate_transient_state(self, voucher):
        """
        Create a new ``Voucher`` which represents the given voucher but which also
        incorporates relevant transient state known to the controller.  For
        example, if a redemption attempt is current in progress, this is
        incorporated.
        """
        if isinstance(voucher.state, model_Pending):
            if voucher.number in self._active:
                return attr.evolve(
                    voucher,
                    state=model_Redeeming(started=self._active[voucher.number]),
                )
            if voucher.number in self._unpaid:
                return attr.evolve(
                    voucher,
                    state=model_Unpaid(finished=self._unpaid[voucher.number]),
                )
            if voucher.number in self._error:
                return attr.evolve(
                    voucher,
                    state=self._error[voucher.number],
                )
        return voucher


def get_redeemer(plugin_name, node_config, announcement, reactor):
    section_name = u"storageclient.plugins.{}".format(plugin_name)
    redeemer_kind = node_config.get_config(
        section=section_name,
        option=u"redeemer",
        default=u"ristretto",
    )
    return _REDEEMERS[redeemer_kind](section_name, node_config, announcement, reactor)


_REDEEMERS = {
    u"non": NonRedeemer.make,
    u"dummy": DummyRedeemer.make,
    u"double-spend": DoubleSpendRedeemer.make,
    u"unpaid": UnpaidRedeemer.make,
    u"error": ErrorRedeemer.make,
    u"ristretto": RistrettoRedeemer.make,
}


@inlineCallbacks
def bracket(first, last, between):
    """
    Invoke an action between two other actions.

    :param first: A no-argument function that may return a Deferred.  It is
        called first.

    :param last: A no-argument function that may return a Deferred.  It is
        called last.

    :param between: A no-argument function that may return a Deferred.  It is
        called after ``first`` is done and completes before ``last`` is called.

    :return Deferred: A ``Deferred`` which fires with the result of
        ``between``.
    """
    yield first()
    try:
        result = yield between()
    except GeneratorExit:
        raise
    except:
        info = exc_info()
        yield last()
        raise info[0], info[1], info[2]
    else:
        yield last()
        returnValue(result)
