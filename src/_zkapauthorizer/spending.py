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

from zope.interface import (
    Interface,
    Attribute,
    implementer,
)

import attr

from .eliot import (
    GET_PASSES,
)

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


@implementer(IPassGroup)
@attr.s
class PassGroup(object):
    """
    Track the state of a group of passes intended as payment for an operation.

    :ivar unicode _message: The request binding message for this group of
        passes.

    :ivar IPassFactory _factory: The factory which created this pass group.

    :ivar list[Pass] passes: The passes of which this group consists.
    """
    _message = attr.ib()
    _factory = attr.ib()
    passes = attr.ib()

    def split(self, select_indices):
        selected = []
        unselected = []
        for idx, p in enumerate(self.passes):
            if idx in select_indices:
                selected.append(p)
            else:
                unselected.append(p)
        return (
            attr.evolve(self, passes=selected),
            attr.evolve(self, passes=unselected),
        )

    def expand(self, by_amount):
        return attr.evolve(
            self,
            passes=self.passes + self._factory.get(self._message, by_amount).passes,
        )

    def mark_spent(self):
        self._factory._mark_spent(self.passes)

    def mark_invalid(self, reason):
        self._factory._mark_invalid(reason, self.passes)

    def reset(self):
        self._factory._reset(self.passes)


@implementer(IPassFactory)
@attr.s
class SpendingController(object):
    """
    A ``SpendingController`` gives out ZKAPs and arranges for re-spend
    attempts when necessary.
    """
    extract_unblinded_tokens = attr.ib()
    tokens_to_passes = attr.ib()

    def get(self, message, num_passes):
        unblinded_tokens = self.extract_unblinded_tokens(num_passes)
        passes = self.tokens_to_passes(message, unblinded_tokens)
        GET_PASSES.log(
            message=message,
            count=num_passes,
        )
        return PassGroup(message, self, passes)

    def _mark_spent(self, group):
        # TODO
        pass

    def _mark_invalid(self, reason, group):
        # TODO
        pass

    def _reset(self, group):
        # TODO
        pass
