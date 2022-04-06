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
A module for logic controlling the manner in which ZKAPs are spent.
"""

from __future__ import annotations

from typing import Callable

import attr
from zope.interface import Attribute, Interface, implementer

from .eliot import GET_PASSES, INVALID_PASSES, RESET_PASSES, SPENT_PASSES
from .model import Pass, UnblindedToken


class IPassGroup(Interface):
    """
    A group of passed meant to be spent together.
    """

    passes = Attribute(":ivar list[Pass] passes: The passes themselves.")

    def split(select_indices):
        """
        Create two new ``IPassGroup`` providers.  The first contains all passes in
        this group at the given indices.  The second contains all the others.

        :param list[int] select_indices: The indices of the passes to include
            in the first resulting group.

        :return (IPassGroup, IPassGroup): The two new groups.
        """

    def expand(by_amount):
        """
        Create a new ``IPassGroup`` provider which contains all of this group's
        passes and some more.

        :param int by_amount: The number of additional passes the resulting
            group should contain.

        :return IPassGroup: The new group.
        """

    def mark_spent():
        """
        The passes have been spent successfully.  Ensure none of them appear in
        any ``IPassGroup`` provider created in the future.

        :return: ``None``
        """

    def mark_invalid(reason):
        """
        The passes could not be spent.  Ensure none of them appear in any
        ``IPassGroup`` provider created in the future.

        :param unicode reason: A short description of the reason the passes
            could not be spent.

        :return: ``None``
        """

    def reset():
        """
        The passes have not been spent.  Return them to for use in a future
        ``IPassGroup`` provider.

        :return: ``None``
        """


class IPassFactory(Interface):
    """
    An object which can create passes.
    """

    def get(message, num_passes):
        """
        :param unicode message: A request-binding message for the resulting passes.

        :param int num_passes: The number of passes to request.

        :return IPassGroup: A group of passes bound to the given message and
            of the requested size.
        """

    def mark_spent(unblinded_tokens: list[UnblindedToken]) -> None:
        """
        See ``IPassGroup.mark_spent``
        """

    def mark_invalid(reason: str, unblinded_tokens: list[UnblindedToken]) -> None:
        """
        See ``IPassGroup.mark_invalid``
        """

    def reset(unblinded_tokens: list[UnblindedToken]) -> None:
        """
        See ``IPassGroup.reset``
        """


@implementer(IPassGroup)
@attr.s
class PassGroup(object):
    """
    Track the state of a group of passes intended as payment for an operation.

    :ivar _message: The request binding message for this group of
        passes.

    :ivar IPassFactory _factory: The factory which created this pass group.

    :ivar list[Pass] passes: The passes of which this group consists.
    """

    _message: bytes = attr.ib(validator=attr.validators.instance_of(bytes))
    _factory: IPassFactory = attr.ib(validator=attr.validators.provides(IPassFactory))
    _tokens: list[tuple[UnblindedToken, Pass]] = attr.ib(
        validator=attr.validators.instance_of(list)
    )

    @property
    def passes(self) -> list[Pass]:
        return list(pass_ for (unblinded_token, pass_) in self._tokens)

    @property
    def unblinded_tokens(self) -> list[UnblindedToken]:
        return list(unblinded_token for (unblinded_token, pass_) in self._tokens)

    def split(self, select_indices: list[int]) -> tuple[PassGroup, PassGroup]:
        selected = []
        unselected = []
        for idx, t in enumerate(self._tokens):
            if idx in select_indices:
                selected.append(t)
            else:
                unselected.append(t)
        return (
            attr.evolve(self, tokens=selected),
            attr.evolve(self, tokens=unselected),
        )

    def expand(self, by_amount: int) -> PassGroup:
        return attr.evolve(
            self,
            tokens=self._tokens + self._factory.get(self._message, by_amount)._tokens,
        )

    def mark_spent(self) -> None:
        self._factory.mark_spent(self.unblinded_tokens)

    def mark_invalid(self, reason) -> None:
        self._factory.mark_invalid(reason, self.unblinded_tokens)

    def reset(self) -> None:
        self._factory.reset(self.unblinded_tokens)


@implementer(IPassFactory)
@attr.s
class SpendingController(object):
    """
    A ``SpendingController`` gives out ZKAPs and arranges for re-spend
    attempts when necessary.
    """

    get_unblinded_tokens: Callable[[int], list[UnblindedToken]] = attr.ib()
    discard_unblinded_tokens: Callable[[list[UnblindedToken]], None] = attr.ib()
    invalidate_unblinded_tokens: Callable[[list[UnblindedToken]], None] = attr.ib()
    reset_unblinded_tokens: Callable[[list[UnblindedToken]], None] = attr.ib()

    tokens_to_passes: Callable[[bytes, list[UnblindedToken]], list[Pass]] = attr.ib()

    @classmethod
    def for_store(cls, tokens_to_passes, store):
        return cls(
            get_unblinded_tokens=store.get_unblinded_tokens,
            discard_unblinded_tokens=store.discard_unblinded_tokens,
            invalidate_unblinded_tokens=store.invalidate_unblinded_tokens,
            reset_unblinded_tokens=store.reset_unblinded_tokens,
            tokens_to_passes=tokens_to_passes,
        )

    def get(self, message, num_passes):
        unblinded_tokens = self.get_unblinded_tokens(num_passes)
        passes = self.tokens_to_passes(message, unblinded_tokens)
        GET_PASSES.log(
            message=message.decode("utf-8"),
            count=num_passes,
        )
        return PassGroup(message, self, list(zip(unblinded_tokens, passes)))

    def mark_spent(self, unblinded_tokens):
        SPENT_PASSES.log(
            count=len(unblinded_tokens),
        )
        self.discard_unblinded_tokens(unblinded_tokens)

    def mark_invalid(self, reason, unblinded_tokens):
        INVALID_PASSES.log(
            reason=reason,
            count=len(unblinded_tokens),
        )
        self.invalidate_unblinded_tokens(reason, unblinded_tokens)

    def reset(self, unblinded_tokens):
        RESET_PASSES.log(
            count=len(unblinded_tokens),
        )
        self.reset_unblinded_tokens(unblinded_tokens)
