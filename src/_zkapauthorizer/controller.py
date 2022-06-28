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

from base64 import b64decode, b64encode
from datetime import timedelta
from functools import partial
from hashlib import sha256
from json import loads
from operator import delitem, setitem

import attr
import challenge_bypass_ristretto
from attrs import define
from treq import content
from treq.client import HTTPClient
from twisted.internet.defer import Deferred, fail, inlineCallbacks, returnValue, succeed
from twisted.internet.task import LoopingCall
from twisted.logger import Logger
from twisted.python.reflect import namedAny
from twisted.python.url import URL
from twisted.web.client import Agent
from zope.interface import Interface, implementer

from ._base64 import urlsafe_b64decode
from ._json import dumps_utf8
from ._stack import less_limited_stack
from .model import Error as model_Error
from .model import Pass
from .model import Pending as model_Pending
from .model import RandomToken
from .model import Redeeming as model_Redeeming
from .model import UnblindedToken
from .model import Unpaid as model_Unpaid
from .model import Voucher

RETRY_INTERVAL = timedelta(milliseconds=1000)


# It would be nice to have frozen exception types but Failure.cleanFailure
# interacts poorly with these.
# https://twistedmatrix.com/trac/ticket/9641
# https://twistedmatrix.com/trac/ticket/9771
@define(auto_exc=False)
class UnexpectedResponse(Exception):
    """
    The issuer responded in an unexpected and unhandled way.
    """

    code: int
    body: bytes


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


@attr.s(auto_attribs=True)
class UnrecognizedFailureReason(Exception):
    """
    An attempt was made to redeem a voucher and the response contained an unknown reason.

    The redemption attempt may be automatically retried at some point.
    """

    response: dict = attr.ib()


@attr.s
class RedemptionResult(object):
    """
    Contain the results of an attempt to redeem a voucher for ZKAP material.

    :ivar unblinded_tokens: The tokens which resulted from the redemption.

    :ivar public_key: The public key which the server proved was involved in
        the redemption process.
    """

    unblinded_tokens: list[UnblindedToken] = attr.ib(
        validator=attr.validators.instance_of(list),
    )
    public_key: str = attr.ib(
        validator=attr.validators.instance_of(str),
    )


class IRedeemer(Interface):
    """
    An ``IRedeemer`` can exchange a voucher for one or more passes.
    """

    def random_tokens_for_voucher(voucher, counter, count):
        """
        Generate a number of random tokens to use in the redemption process for
        the given voucher.

        :param Voucher voucher: The voucher the tokens will be associated
            with.

        :param int counter: See ``redeemWithCounter``.

        :param int count: The number of random tokens to generate.

        :return list[RandomToken]: The generated tokens.  Random tokens must
            be unique over the lifetime of the Tahoe-LAFS node where this
            plugin is being used but the same tokens *may* be generated for
            the same voucher.  The tokens must be kept secret to preserve the
            anonymity property of the system.
        """

    def redeemWithCounter(voucher, counter, random_tokens):
        """
        Redeem a voucher for unblinded tokens which can be used to construct
        passes.

        Implementations of this method do not need to be fault tolerant.  If a
        redemption attempt is interrupted before it completes, it is the
        caller's responsibility to call this method again with the same
        arguments.

        :param Voucher voucher: The voucher to redeem.

        :param int counter: The counter to use in this redemption attempt.  To
            support vouchers which can be redeemed for a larger number of
            tokens than is practical to handle at once, one voucher can be
            partially redeemed repeatedly until the complete set of tokens has
            been received.  Each partial redemption must have a distinct
            counter value.

        :param list[RandomToken] random_tokens: The random tokens to use in
            the redemption process.

        :return: A ``Deferred`` which fires with a ``RedemptionResult``
            instance or which fails with any error to allow a retry to be made
            at some future point.  It may also fail with an ``AlreadySpent``
            error to indicate the redemption server considers the voucher to
            have been redeemed already and will not allow it to be redeemed.
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


@attr.s
@implementer(IRedeemer)
class IndexedRedeemer(object):
    """
    A ``IndexedRedeemer`` delegates redemption to a redeemer chosen to
    correspond to the redemption counter given.
    """

    _log = Logger()

    redeemers = attr.ib()

    def tokens_to_passes(self, message, unblinded_tokens):
        raise NotImplementedError("IndexedRedeemer cannot create passes")

    def random_tokens_for_voucher(self, voucher, counter, count):
        return dummy_random_tokens(voucher, counter, count)

    def redeemWithCounter(self, voucher, counter, random_tokens):
        self._log.info(
            "IndexedRedeemer redeeming {voucher}[{counter}] using {delegate}.",
            voucher=voucher,
            counter=counter,
            delegate=self.redeemers[counter],
        )
        return self.redeemers[counter].redeemWithCounter(
            voucher,
            counter,
            random_tokens,
        )


@implementer(IRedeemer)
class NonRedeemer(object):
    """
    A ``NonRedeemer`` never tries to redeem vouchers for ZKAPs.
    """

    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        return cls()

    def random_tokens_for_voucher(self, voucher, counter, count):
        return dummy_random_tokens(voucher, counter, count)

    def redeemWithCounter(self, voucher, counter, random_tokens):
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

    details = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        details = node_config.get_config(
            section=section_name,
            option="details",
        )
        return cls(details)

    def random_tokens_for_voucher(self, voucher, counter, count):
        return dummy_random_tokens(voucher, counter, count)

    def redeemWithCounter(self, voucher, counter, random_tokens):
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

    def tokens_to_passes(self, message, unblinded_tokens):
        raise NotImplementedError("DoubleSpendRedeemer cannot create passes")

    def random_tokens_for_voucher(self, voucher, counter, count):
        return dummy_random_tokens(voucher, counter, count)

    def redeemWithCounter(self, voucher, counter, random_tokens):
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

    def tokens_to_passes(self, message, unblinded_tokens):
        raise NotImplementedError("UnpaidRedeemer cannot create passes")

    def random_tokens_for_voucher(self, voucher, counter, count):
        return dummy_random_tokens(voucher, counter, count)

    def redeemWithCounter(self, voucher, counter, random_tokens):
        return fail(Unpaid(voucher))


@implementer(IRedeemer)
@attr.s
class RecordingRedeemer(object):
    """
    A ``CountingRedeemer`` delegates redemption logic to another object but
    records all redemption attempts.
    """

    original = attr.ib()
    redemptions = attr.ib(default=attr.Factory(list))

    def tokens_to_passes(self, message, unblinded_tokens):
        return self.original.tokens_to_passes(message, unblinded_tokens)

    def random_tokens_for_voucher(self, voucher, counter, count):
        return dummy_random_tokens(voucher, counter, count)

    def redeemWithCounter(self, voucher, counter, random_tokens):
        self.redemptions.append((voucher, counter, random_tokens))
        return self.original.redeemWithCounter(voucher, counter, random_tokens)


def dummy_random_tokens(voucher, counter, count):
    v = urlsafe_b64decode(voucher.number)

    def dummy_random_token(n):
        return RandomToken(
            # Padding is 96 (random token length) - 32 (decoded voucher
            # length) - 4 (fixed-width counter)
            b64encode(
                v + "{:0>4}{:0>60}".format(counter, n).encode("ascii"),
            ),
        )

    return list(dummy_random_token(n) for n in range(count))


@implementer(IRedeemer)
@attr.s
class DummyRedeemer(object):
    """
    A ``DummyRedeemer`` pretends to redeem vouchers for ZKAPs.  Instead of
    really redeeming them, it makes up some fake ZKAPs and pretends those are
    the result.

    :ivar str _public_key: The base64-encoded public key to return with
        all successful redemption results.  As with the tokens returned by
        this redeemer, chances are this is not actually a valid public key.
        Its corresponding private key certainly has not been used to sign
        anything.
    """

    _public_key = attr.ib(
        validator=attr.validators.instance_of(str),
    )

    @classmethod
    def make(cls, section_name, node_config, announcement, reactor):
        return cls(
            node_config.get_config(
                section=section_name,
                option="issuer-public-key",
            ),
        )

    def random_tokens_for_voucher(self, voucher, counter, count):
        """
        Generate some number of random tokens to submit along with a voucher for
        redemption.
        """
        return dummy_random_tokens(voucher, counter, count)

    def redeemWithCounter(self, voucher, counter, random_tokens):
        """
        :return: An already-fired ``Deferred`` that has a list of
          ``UnblindedToken`` instances wrapping meaningless values.
        """
        if not isinstance(voucher, Voucher):
            raise TypeError(
                "Got {}, expected instance of Voucher".format(
                    voucher,
                ),
            )

        def dummy_unblinded_token(random_token):
            random_value = b64decode(random_token.token_value)
            unblinded_value = random_value + b"x" * (96 - len(random_value))
            return UnblindedToken(b64encode(unblinded_value))

        return succeed(
            RedemptionResult(
                list(dummy_unblinded_token(token) for token in random_tokens),
                self._public_key,
            ),
        )

    def tokens_to_passes(self, message, unblinded_tokens):
        def token_to_pass(token):
            # Generate distinct strings based on the unblinded token which we
            # can include in the resulting Pass.  This ensures the pass values
            # will be unique if and only if the unblinded tokens were unique
            # (barring improbable hash collisions).
            token_digest = sha256(token.unblinded_token).hexdigest().encode("ascii")

            preimage = b"preimage-" + token_digest[len(b"preimage-") :]
            signature = b"signature-" + token_digest[len(b"signature-") :]
            return Pass(
                b64encode(preimage),
                b64encode(signature),
            )

        return list(token_to_pass(token) for token in unblinded_tokens)


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
        return "Announced issuer ({}) disagrees with configured issuer ({}).".format(
            *self.args
        )


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
            option="ristretto-issuer-root-url",
        )
        if announcement is not None:
            # Don't let us talk to a storage server that has a different idea
            # about who issues ZKAPs.  If we did, they *probably* wouldn't
            # accept our ZKAPs since they should have the wrong signature.
            #
            # We should lift this limitation (that is, we should support as
            # many different issuers as the user likes) in the future but
            # doing so requires changing how the web interface works and
            # possibly also the interface for voucher submission.
            #
            # If we aren't given an announcement then we're not being used in
            # the context of a specific storage server so the check is
            # unnecessary and impossible.
            announced_issuer = announcement["ristretto-issuer-root-url"]
            if announced_issuer != configured_issuer:
                raise IssuerConfigurationMismatch(announced_issuer, configured_issuer)

        return cls(
            HTTPClient(Agent(reactor)),
            URL.from_text(configured_issuer),
        )

    def random_tokens_for_voucher(self, voucher, counter, count):
        return list(
            RandomToken(
                challenge_bypass_ristretto.RandomToken.create().encode_base64(),
            )
            for n in range(count)
        )

    @inlineCallbacks
    def redeemWithCounter(self, voucher, counter, encoded_random_tokens):
        random_tokens = list(
            challenge_bypass_ristretto.RandomToken.decode_base64(token.token_value)
            for token in encoded_random_tokens
        )
        blinded_tokens = list(token.blind() for token in random_tokens)
        response = yield self._treq.post(
            self._api_root.child("v1", "redeem").to_text(),
            dumps_utf8(
                {
                    "redeemVoucher": voucher.number.decode("ascii"),
                    "redeemCounter": counter,
                    "redeemTokens": list(
                        token.encode_base64().decode("ascii")
                        for token in blinded_tokens
                    ),
                }
            ),
            headers={b"content-type": b"application/json"},
        )
        response_body = yield content(response)

        try:
            result = loads(response_body)
        except ValueError:
            raise UnexpectedResponse(response.code, response_body)

        success = result.get("success", False)
        if not success:
            reason = result.get("reason", None)
            if reason == "double-spend":
                raise AlreadySpent(voucher)
            elif reason == "unpaid":
                raise Unpaid(voucher)

            raise UnrecognizedFailureReason(result)

        self._log.info(
            "Redeemed: {public_key} {proof} {count}",
            public_key=result["public-key"],
            proof=result["proof"],
            count=len(result["signatures"]),
        )

        marshaled_signed_tokens = result["signatures"]
        marshaled_proof = result["proof"]
        marshaled_public_key = result["public-key"]

        public_key = challenge_bypass_ristretto.PublicKey.decode_base64(
            marshaled_public_key.encode("ascii"),
        )
        self._log.info("Decoded public key")
        clients_signed_tokens = list(
            challenge_bypass_ristretto.SignedToken.decode_base64(
                marshaled_signed_token.encode("ascii"),
            )
            for marshaled_signed_token in marshaled_signed_tokens
        )
        self._log.info("Decoded signed tokens")
        clients_proof = challenge_bypass_ristretto.BatchDLEQProof.decode_base64(
            marshaled_proof.encode("ascii"),
        )
        with less_limited_stack():
            self._log.info("Decoded batch proof")
            clients_unblinded_tokens = clients_proof.invalid_or_unblind(
                random_tokens,
                blinded_tokens,
                clients_signed_tokens,
                public_key,
            )
        self._log.info("Validated proof")
        unblinded_tokens = list(
            UnblindedToken(token.encode_base64()) for token in clients_unblinded_tokens
        )
        returnValue(
            RedemptionResult(
                unblinded_tokens,
                marshaled_public_key,
            )
        )

    def tokens_to_passes(self, message, unblinded_tokens):
        assert isinstance(message, bytes)
        assert isinstance(unblinded_tokens, list)
        assert all(isinstance(element, UnblindedToken) for element in unblinded_tokens)
        unblinded_tokens = list(
            challenge_bypass_ristretto.UnblindedToken.decode_base64(
                token.unblinded_token
            )
            for token in unblinded_tokens
        )
        clients_verification_keys = list(
            token.derive_verification_key_sha512() for token in unblinded_tokens
        )
        clients_signatures = list(
            verification_key.sign_sha512(message)
            for verification_key in clients_verification_keys
        )
        clients_preimages = list(token.preimage() for token in unblinded_tokens)
        passes = list(
            Pass(
                preimage.encode_base64(),
                signature.encode_base64(),
            )
            for (preimage, signature) in zip(clients_preimages, clients_signatures)
        )
        return passes


def token_count_for_group(num_groups, total_tokens, group_number):
    """
    Determine a number of tokens to retrieve for a particular group out of an
    overall redemption attempt.

    :param int num_groups: The total number of groups the tokens will be
        divided into.

    :param int total_tokens: The total number of tokens to divide up.

    :param int group_number: The particular group for which to determine a
        token count.

    :return int: A number of tokens to redeem in this group.
    """
    if total_tokens < num_groups:
        raise ValueError(
            "Cannot distribute {} tokens among {} groups coherently.".format(
                total_tokens,
                num_groups,
            ),
        )
    if group_number >= num_groups or group_number < 0:
        raise ValueError(
            "Group number {} is out of valid range [0..{})".format(
                group_number,
                num_groups,
            ),
        )
    group_size, remainder = divmod(total_tokens, num_groups)
    if group_number < remainder:
        return group_size + 1
    return group_size


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

    :ivar int default_token_count: The number of tokens to request when
        redeeming a voucher, if no other count is given when the redemption is
        started.

    :ivar set[str] allowed_public_keys: The base64-encoded public keys for
        which to accept tokens.

    :ivar dict[str, Redeeming] _active: A mapping from voucher identifiers
        which currently have redemption attempts in progress to a
        ``Redeeming`` state representing the attempt.

    :ivar dict[str, datetime] _error: A mapping from voucher identifiers
        which have recently failed with an unrecognized, transient error.

    :ivar dict[str, datetime] _unpaid: A mapping from voucher identifiers
        which have recently failed a redemption attempt due to an unpaid
        response from the redemption server to timestamps when the failure was
        observed.

    :ivar int num_redemption_groups: The number of groups into which to divide
        tokens during the redemption process, with each group being redeemed
        separately from the rest.  This value needs to agree with the value
        the PaymentServer is configured with.

        TODO: Retrieve this value from the PaymentServer or from the
        ZKAPAuthorizer configuration instead of just hard-coding a duplicate
        value in this implementation.

    :ivar IReactorTime _clock: The reactor to use for scheduling redemption
        retries.
    """

    _log = Logger()

    store = attr.ib()
    redeemer = attr.ib()
    default_token_count = attr.ib()

    allowed_public_keys = attr.ib(validator=attr.validators.instance_of(set))

    num_redemption_groups = attr.ib(default=16)

    _clock = attr.ib(default=None)

    _error = attr.ib(default=attr.Factory(dict))
    _unpaid = attr.ib(default=attr.Factory(dict))
    _active = attr.ib(default=attr.Factory(dict))

    def __attrs_post_init__(self):
        """
        Check the voucher store for any vouchers in need of redemption.

        This is an initialization-time hook called by attrs.
        """
        if self._clock is None:
            self._clock = namedAny("twisted.internet.reactor")

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
        for voucher in list(self._error.keys()) + list(self._unpaid.keys()):
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

    def _get_random_tokens_for_voucher(
        self, voucher, counter, num_tokens, total_tokens
    ):
        """
        Generate or load random tokens for a redemption attempt of a voucher.

        :param int num_tokens: The number of tokens to get.

        :param int total_tokens: The total number of tokens for which this
            voucher is expected to be redeemed.
        """

        def get_tokens():
            self._log.info(
                "Generating random tokens for a voucher ({voucher}).",
                voucher=voucher,
            )
            return self.redeemer.random_tokens_for_voucher(
                Voucher(
                    number=voucher,
                    # Unclear whether this information is useful to redeemers
                    # but we cannot construct a Voucher without some value
                    # here.
                    expected_tokens=total_tokens,
                ),
                counter,
                num_tokens,
            )

        return self.store.add(
            voucher,
            total_tokens,
            counter,
            get_tokens,
        )

    @inlineCallbacks
    def redeem(self, voucher, num_tokens=None):
        """
        :param bytes voucher: A voucher to redeem.

        :param int num_tokens: A number of tokens to redeem.
        """
        # Try to get an existing voucher object for the given number.
        try:
            voucher_obj = self.store.get(voucher)
        except KeyError:
            # This is our first time dealing with this number.
            counter_start = 0
            if num_tokens is None:
                num_tokens = self.default_token_count
        else:
            num_tokens = voucher_obj.expected_tokens
            # Determine the starting point from the state.
            if voucher_obj.state.should_start_redemption():
                counter_start = voucher_obj.state.counter
            else:
                raise ValueError(
                    "Cannot redeem voucher in state {}.".format(
                        voucher_obj.state,
                    ),
                )

        self._log.info(
            "Starting redemption of {voucher}[{start}..{end}] for {num_tokens} tokens.",
            voucher=voucher,
            start=counter_start,
            end=self.num_redemption_groups,
            num_tokens=num_tokens,
        )
        for counter in range(counter_start, self.num_redemption_groups):
            # Pre-generate the random tokens to use when redeeming the voucher.
            # These are persisted with the voucher so the redemption can be made
            # idempotent.  We don't want to lose the value if we fail after the
            # server deems the voucher redeemed but before we persist the result.
            # With a stable set of tokens, we can re-submit them and the server
            # can re-sign them without fear of issuing excess passes.  Whether the
            # server signs a given set of random tokens once or many times, the
            # number of passes that can be constructed is still only the size of
            # the set of random tokens.
            token_count = token_count_for_group(
                self.num_redemption_groups, num_tokens, counter
            )
            tokens = self._get_random_tokens_for_voucher(
                voucher,
                counter,
                num_tokens=token_count,
                total_tokens=num_tokens,
            )

            # Reload state before each iteration.  We expect it to change each time.
            voucher_obj = self.store.get(voucher)

            succeeded = yield self._perform_redeem(voucher_obj, counter, tokens)
            if not succeeded:
                self._log.info(
                    "Temporarily suspending redemption of {voucher} after non-success result.",
                    voucher=voucher,
                )
                break

    def _perform_redeem(self, voucher, counter, random_tokens):
        """
        Use the redeemer to redeem the given voucher and random tokens.

        This will not persist the voucher or random tokens but it will persist
        the result.

        :return Deferred[bool]: A ``Deferred`` firing with ``True`` if and
            only if redemption succeeds.
        """
        if not isinstance(voucher.state, model_Pending):
            raise ValueError(
                "Cannot redeem voucher in state {} instead of Pending.".format(
                    voucher.state,
                ),
            )

        # Ask the redeemer to do the real task of redemption.
        self._log.info(
            "Redeeming random tokens for a voucher ({voucher}).", voucher=voucher
        )
        d = bracket(
            lambda: setitem(
                self._active,
                voucher.number,
                model_Redeeming(
                    started=self.store.now(),
                    counter=voucher.state.counter,
                ),
            ),
            lambda: delitem(self._active, voucher.number),
            lambda: self.redeemer.redeemWithCounter(voucher, counter, random_tokens),
        )
        d.addCallbacks(
            partial(self._redeem_success, voucher.number, counter),
            partial(self._redeem_failure, voucher.number),
        )
        d.addErrback(partial(self._final_redeem_error, voucher.number))
        return d

    def _redeem_success(self, voucher, counter, result):
        """
        Update the database state to reflect that a voucher was redeemed and to
        store the resulting unblinded tokens (which can be used to construct
        passes later).
        """
        self._log.info(
            "Inserting redeemed unblinded tokens for a voucher ({voucher}).",
            voucher=voucher,
        )
        self.store.insert_unblinded_tokens_for_voucher(
            voucher,
            result.public_key,
            result.unblinded_tokens,
            completed=(counter + 1 == self.num_redemption_groups),
            spendable=result.public_key in self.allowed_public_keys,
        )
        return True

    def _redeem_failure(self, voucher, reason):
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
                "Redeeming random tokens for a voucher ({voucher}) failed: {reason!r}",
                reason=reason.value,
                voucher=voucher,
            )
            self._error[voucher] = model_Error(
                finished=self.store.now(),
                details=reason.getErrorMessage(),
            )
        return False

    def _final_redeem_error(self, voucher, reason):
        self._log.failure(
            "Redeeming random tokens for a voucher ({voucher}) encountered error.",
            reason,
            voucher=voucher,
        )
        return False

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
                    state=self._active[voucher.number],
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
    section_name = "storageclient.plugins.{}".format(plugin_name)
    redeemer_kind = node_config.get_config(
        section=section_name,
        option="redeemer",
        default="ristretto",
    )
    return _REDEEMERS[redeemer_kind](section_name, node_config, announcement, reactor)


_REDEEMERS = {
    "non": NonRedeemer.make,
    "dummy": DummyRedeemer.make,
    "double-spend": DoubleSpendRedeemer.make,
    "unpaid": UnpaidRedeemer.make,
    "error": ErrorRedeemer.make,
    "ristretto": RistrettoRedeemer.make,
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
        yield last()
        raise
    else:
        yield last()
        returnValue(result)
