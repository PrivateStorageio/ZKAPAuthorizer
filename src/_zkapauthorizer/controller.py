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

from functools import (
    partial,
)

import attr

from zope.interface import (
    Interface,
    implementer,
)

from twisted.internet.defer import (
    Deferred,
    succeed,
)

from .foolscap import (
    TOKEN_LENGTH,
)
from .model import (
    Pass,
    RandomToken,
)


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
        Redeem a voucher for passes.

        Implementations of this method do not need to be fault tolerant.  If a
        redemption attempt is interrupted before it completes, it is the
        caller's responsibility to call this method again with the same
        arguments.

        :param Voucher voucher: The voucher to redeem.

        :param list[RandomToken] random_tokens: The random tokens to use in
            the redemption process.

        :return: A ``Deferred`` which fires with a list of ``Pass`` instances
            on successful redemption or which fails with
            ``TransientRedemptionError`` on any error which may be resolved by
            simply trying again later or which fails with
            ``PermanentRedemptionError`` on any error which is definitive and
            final.
        """


@implementer(IRedeemer)
class NonRedeemer(object):
    """
    A ``NonRedeemer`` never tries to redeem vouchers for ZKAPs.
    """
    def random_tokens_for_voucher(self, voucher, count):
        # It doesn't matter because we're never going to try to redeem them.
        return list(
            RandomToken(u"{}-{}".format(voucher, n))
            for n
            in range(count)
        )

    def redeem(self, voucher, random_tokens):
        # Don't try to redeem them.
        return Deferred()


@implementer(IRedeemer)
@attr.s
class DummyRedeemer(object):
    """
    A ``DummyRedeemer`` pretends to redeem vouchers for ZKAPs.  Instead of
    really redeeming them, it makes up some fake ZKAPs and pretends those are
    the result.
    """
    def random_tokens_for_voucher(self, voucher, count):
        """
        Generate some number of random tokens to submit along with a voucher for
        redemption.
        """
        # Dummy token generation.
        return list(
            RandomToken(u"{}-{}".format(voucher, n))
            for n
            in range(count)
        )

    def redeem(self, voucher, random_tokens):
        """
        :return: An already-fired ``Deferred`` that has a list of ``Pass``
            instances wrapping meaningless values.
        """
        return succeed(
            list(
                Pass((u"pass-" + token.token_value).zfill(TOKEN_LENGTH))
                for token
                in random_tokens
            ),
        )


@attr.s
class PaymentController(object):
    """
    The ``PaymentController`` coordinates the process of turning a voucher
    into a collection of ZKAPs:

      1. A voucher to be consumed is handed to the controller.
         Once a voucher is handed over to the controller the controller takes all responsibility for it.

      2. The controller tells the data store to remember the voucher.
         The data store provides durability for the voucher which represents an investment (ie, a purchase) on the part of the client.

      3. The controller tells the store to hand all currently idle vouchers to a redeemer.
         In normal operation, only the newly added voucher will be idle.


    """
    store = attr.ib()
    redeemer = attr.ib()

    def redeem(self, voucher):
        # Pre-generate the random tokens to use when redeeming the voucher.
        # These are persisted with the voucher so the redemption can be made
        # idempotent.  We don't want to lose the value if we fail after the
        # server deems the voucher redeemed but before we persist the result.
        # With a stable set of tokens, we can re-submit them and the server
        # can re-sign them without fear of issuing excess passes.  Whether the
        # server signs a given set of random tokens once or many times, the
        # number of passes that can be constructed is still only the size of
        # the set of random tokens.
        tokens = self.redeemer.random_tokens_for_voucher(voucher, 100)

        # Persist the voucher and tokens so they're available if we fail.
        self.store.add(voucher, tokens)

        # Ask the redeemer to do the real task of redemption.
        d = self.redeemer.redeem(voucher, tokens)
        d.addCallback(
            partial(self._redeemSuccess, voucher),
        )

    def _redeemSuccess(self, voucher, passes):
        """
        Update the database state to reflect that a voucher was redeemed and to
        store the resulting passes.
        """
        self.store.insert_passes_for_voucher(voucher, passes)
