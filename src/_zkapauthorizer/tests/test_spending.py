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
Tests for ``_zkapauthorizer.spending``.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

from future.utils import PY2

if  PY2:
    from future.builtins import (  # noqa: F401
        filter,
        map,
        zip,
        ascii,
        chr,
        hex,
        input,
        next,
        oct,
        open,
        pow,
        round,
        super,
        bytes,
        dict,
        list,
        object,
        range,
        str,
        max,
        min,
    )

from hypothesis import given
from hypothesis.strategies import data, integers, randoms
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    Equals,
    HasLength,
    MatchesAll,
    MatchesStructure,
)
from testtools.twistedsupport import succeeded

from ..spending import IPassGroup, SpendingController
from .fixtures import ConfiglessMemoryVoucherStore
from .matchers import Provides
from .strategies import pass_counts, posix_safe_datetimes, vouchers


class PassGroupTests(TestCase):
    """
    Tests for ``IPassGroup`` and the factories that create them.
    """

    @given(vouchers(), pass_counts(), posix_safe_datetimes())
    def test_get(self, voucher, num_passes, now):
        """
        ``IPassFactory.get`` returns an ``IPassGroup`` provider containing the
        requested number of passes.
        """
        configless = self.useFixture(
            ConfiglessMemoryVoucherStore(
                lambda: now,
            ),
        )
        # Make sure there are enough tokens for us to extract!
        self.assertThat(
            configless.redeem(voucher, num_passes),
            succeeded(Always()),
        )

        pass_factory = SpendingController.for_store(
            tokens_to_passes=configless.redeemer.tokens_to_passes,
            store=configless.store,
        )

        group = pass_factory.get(b"message", num_passes)
        self.assertThat(
            group,
            MatchesAll(
                Provides([IPassGroup]),
                MatchesStructure(
                    passes=HasLength(num_passes),
                ),
            ),
        )

    def _test_token_group_operation(
        self,
        operation,
        matches_tokens,
        voucher,
        num_passes,
        now,
        random,
        data,
    ):
        configless = self.useFixture(
            ConfiglessMemoryVoucherStore(
                lambda: now,
            ),
        )
        # Make sure there are enough tokens for us to use!
        self.assertThat(
            configless.redeem(voucher, num_passes),
            succeeded(Always()),
        )

        # Figure out some subset, maybe empty, of passes from the group that
        # we will try to operate on.
        group_size = data.draw(integers(min_value=0, max_value=num_passes))
        indices = list(range(num_passes))
        random.shuffle(indices)
        spent_indices = indices[:group_size]

        # Get some passes and perform the operation.
        pass_factory = SpendingController.for_store(
            tokens_to_passes=configless.redeemer.tokens_to_passes,
            store=configless.store,
        )
        group = pass_factory.get(b"message", num_passes)
        spent, rest = group.split(spent_indices)
        operation(spent)

        # Verify the expected outcome of the operation using the supplied
        # matcher factory.
        self.assertThat(
            configless.store,
            matches_tokens(num_passes, spent),
        )

    @given(vouchers(), pass_counts(), posix_safe_datetimes(), randoms(), data())
    def test_spent(self, voucher, num_passes, now, random, data):
        """
        Passes in a group can be marked as successfully spent to prevent them from
        being re-used by a future ``get`` call.
        """

        def matches_tokens(num_passes, group):
            return AfterPreprocessing(
                # The use of `backup` here to check is questionable.  TODO:
                # Straight-up query interface for tokens in different states.
                lambda store: store.backup()[u"unblinded-tokens"],
                HasLength(num_passes - len(group.passes)),
            )

        return self._test_token_group_operation(
            lambda group: group.mark_spent(),
            matches_tokens,
            voucher,
            num_passes,
            now,
            random,
            data,
        )

    @given(vouchers(), pass_counts(), posix_safe_datetimes(), randoms(), data())
    def test_invalid(self, voucher, num_passes, now, random, data):
        """
        Passes in a group can be marked as invalid to prevent them from being
        re-used by a future ``get`` call.
        """

        def matches_tokens(num_passes, group):
            return AfterPreprocessing(
                # The use of `backup` here to check is questionable.  TODO:
                # Straight-up query interface for tokens in different states.
                lambda store: store.backup()[u"unblinded-tokens"],
                HasLength(num_passes - len(group.passes)),
            )

        return self._test_token_group_operation(
            lambda group: group.mark_invalid(u"reason"),
            matches_tokens,
            voucher,
            num_passes,
            now,
            random,
            data,
        )

    @given(vouchers(), pass_counts(), posix_safe_datetimes(), randoms(), data())
    def test_reset(self, voucher, num_passes, now, random, data):
        """
        Passes in a group can be reset to allow them to be re-used by a future
        ``get`` call.
        """

        def matches_tokens(num_passes, group):
            return AfterPreprocessing(
                # They've been reset so we should be able to re-get them.
                lambda store: store.get_unblinded_tokens(len(group.passes)),
                Equals(group.unblinded_tokens),
            )

        return self._test_token_group_operation(
            lambda group: group.reset(),
            matches_tokens,
            voucher,
            num_passes,
            now,
            random,
            data,
        )
