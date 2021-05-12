# Copyright 2020 PrivateStorage.io, LLC
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
Tests for ``_zkapauthorizer._storage_client``.
"""

from __future__ import (
    division,
)

from functools import (
    partial,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    Always,
    Is,
    Equals,
    AfterPreprocessing,
    MatchesStructure,
    HasLength,
    MatchesAll,
    AllMatch,
    IsInstance,
)
from testtools.twistedsupport import (
    succeeded,
    failed,
)

from hypothesis import (
    given,
)
from hypothesis.strategies import (
    sampled_from,
)

from twisted.internet.defer import (
    succeed,
    fail,
)

from .matchers import (
    even,
    odd,
    raises,
)

from .strategies import (
    pass_counts,
)

from ..api import (
    MorePassesRequired,
)
from ..model import (
    NotEnoughTokens,
)
from .._storage_client import (
    call_with_passes,
)
from .._storage_server import (
    _ValidationResult,
)

from .storage_common import (
    pass_factory,
    integer_passes,
)


class CallWithPassesTests(TestCase):
    """
    Tests for ``call_with_passes``.
    """
    @given(pass_counts())
    def test_success_result(self, num_passes):
        """
        ``call_with_passes`` returns a ``Deferred`` that fires with the same
        success result as that of the ``Deferred`` returned by the method
        passed in.
        """
        result = object()
        self.assertThat(
            call_with_passes(
                lambda group: succeed(result),
                num_passes,
                partial(pass_factory(integer_passes(num_passes)).get, u"message"),
            ),
            succeeded(Is(result)),
        )

    @given(pass_counts())
    def test_failure_result(self, num_passes):
        """
        ``call_with_passes`` returns a ``Deferred`` that fires with the same
        failure result as that of the ``Deferred`` returned by the method
        passed in if that failure is not a ``MorePassesRequired``.
        """
        result = Exception()
        self.assertThat(
            call_with_passes(
                lambda group: fail(result),
                num_passes,
                partial(pass_factory(integer_passes(num_passes)).get, u"message"),
            ),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    Is(result),
                ),
            ),
        )

    @given(pass_counts())
    def test_passes_issued(self, num_passes):
        """
        ``call_with_passes`` calls the given method with an ``IPassGroup``
        provider containing ``num_passes`` created by the function passed for
        ``get_passes``.
        """
        passes = pass_factory(integer_passes(num_passes))

        self.assertThat(
            call_with_passes(
                lambda group: succeed(group.passes),
                num_passes,
                partial(passes.get, u"message"),
            ),
            succeeded(
                Equals(
                    sorted(passes.issued),
                ),
            ),
        )

    @given(pass_counts())
    def test_passes_spent_on_success(self, num_passes):
        """
        ``call_with_passes`` marks the passes it uses as spent if the operation
        succeeds.
        """
        passes = pass_factory(integer_passes(num_passes))

        self.assertThat(
            call_with_passes(
                lambda group: None,
                num_passes,
                partial(passes.get, u"message"),
            ),
            succeeded(Always()),
        )
        self.assertThat(
            passes.issued,
            Equals(passes.spent),
        )

    @given(pass_counts())
    def test_passes_returned_on_failure(self, num_passes):
        """
        ``call_with_passes`` returns the passes it uses if the operation fails.
        """
        passes = pass_factory(integer_passes(num_passes))

        self.assertThat(
            call_with_passes(
                lambda group: fail(Exception("Anything")),
                num_passes,
                partial(passes.get, u"message"),
            ),
            failed(Always()),
        )
        self.assertThat(
            passes,
            MatchesStructure(
                issued=Equals(set(passes.returned)),
                spent=Equals(set()),
            ),
        )

    @given(pass_counts())
    def test_retry_on_rejected_passes(self, num_passes):
        """
        ``call_with_passes`` tries calling the given method again with a new list
        of passes, still of length ```num_passes``, but without the passes
        which were rejected on the first try.
        """
        # Half of the passes are going to be rejected so make twice as many as
        # the operation uses available.
        passes = pass_factory(integer_passes(num_passes * 2))

        def reject_even_pass_values(group):
            passes = group.passes
            good_passes = list(idx for (idx, p) in enumerate(passes) if p % 2)
            bad_passes = list(idx for (idx, p) in enumerate(passes) if idx not in good_passes)
            if len(good_passes) < num_passes:
                _ValidationResult(
                    valid=good_passes,
                    signature_check_failed=bad_passes,
                ).raise_for(num_passes)
            return None

        self.assertThat(
            call_with_passes(
                reject_even_pass_values,
                num_passes,
                partial(passes.get, u"message"),
            ),
            succeeded(Always()),
        )
        self.assertThat(
            passes,
            MatchesStructure(
                returned=HasLength(0),
                in_use=HasLength(0),
                invalid=MatchesAll(
                    HasLength(num_passes),
                    AllMatch(even()),
                ),
                spent=MatchesAll(
                    HasLength(num_passes),
                    AllMatch(odd()),
                ),
                issued=Equals(passes.spent | set(passes.invalid.keys())),
            ),
        )

    @given(pass_counts())
    def test_pass_through_too_few_passes(self, num_passes):
        """
        ``call_with_passes`` lets ``MorePassesRequired`` propagate through it if
        no passes have been marked as invalid.  This happens if all passes
        given were valid but too fewer were given.
        """
        passes = pass_factory(integer_passes(num_passes))

        def reject_passes(group):
            passes = group.passes
            _ValidationResult(
                valid=range(len(passes)),
                signature_check_failed=[],
            ).raise_for(len(passes) + 1)

        self.assertThat(
            call_with_passes(
                reject_passes,
                num_passes,
                partial(passes.get, u"message"),
            ),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    Equals(
                        MorePassesRequired(
                            valid_count=num_passes,
                            required_count=num_passes + 1,
                            signature_check_failed=[],
                        ),
                    ),
                ),
            ),
        )

        # The passes in the group that was rejected are also returned for
        # later use.
        self.assertThat(
            passes,
            MatchesStructure(
                spent=HasLength(0),
                returned=HasLength(num_passes),
            ),
        )

    @given(pass_counts(), pass_counts())
    def test_not_enough_tokens_for_retry(self, num_passes, extras):
        """
        When there are not enough tokens to successfully complete a retry with the
        required number of passes, ``call_with_passes`` marks all passes
        reported as invalid during its efforts as such and resets all other
        passes it acquired.
        """
        passes = pass_factory(integer_passes(num_passes + extras))
        rejected = []
        accepted = []

        def reject_half_passes(group):
            num = len(group.passes)
            # Floor division will always short-change valid here, even for a
            # group size of 1.  Therefore there will always be some passes
            # marked as invalid.
            accept_indexes = range(num // 2)
            reject_indexes = range(num // 2, num)
            # Only keep this iteration's accepted passes.  We'll want to see
            # that the final iteration's passes are all returned.  Passes from
            # earlier iterations don't matter.
            accepted[:] = list(group.passes[i] for i in accept_indexes)
            # On the other hand, keep *all* rejected passes.  They should all
            # be marked as invalid and we want to make sure that's the case,
            # no matter which iteration rejected them.
            rejected.extend(group.passes[i] for i in reject_indexes)
            _ValidationResult(
                valid=accept_indexes,
                signature_check_failed=reject_indexes,
            ).raise_for(num)

        self.assertThat(
            call_with_passes(
                # Since half of every group is rejected, we'll eventually run
                # out of passes no matter how many we start with.
                reject_half_passes,
                num_passes,
                partial(passes.get, u"message"),
            ),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(NotEnoughTokens),
                ),
            ),
        )
        self.assertThat(
            passes,
            MatchesStructure(
                # Whatever is left in the group when we run out of tokens must
                # be returned.
                returned=Equals(accepted),
                in_use=HasLength(0),
                invalid=AfterPreprocessing(
                    lambda invalid: set(invalid.keys()),
                    Equals(set(rejected)),
                ),
                spent=HasLength(0),
                issued=Equals(set(accepted + rejected)),
            ),
        )

def reset(group):
    group.reset()

def spend(group):
    group.mark_spent()

def invalidate(group):
    group.mark_invalid(u"reason")


class PassFactoryTests(TestCase):
    """
    Tests for ``pass_factory``.

    It is unfortunate that this isn't the same test suite as
    ``test_spending.PassGroupTests``.
    """
    @given(pass_counts(), pass_counts())
    def test_returned_passes_reused(self, num_passes_a, num_passes_b):
        """
        ``IPassGroup.reset`` makes passes available to be returned by
        ``IPassGroup.get`` again.
        """
        message = u"message"
        min_passes = min(num_passes_a, num_passes_b)
        max_passes = max(num_passes_a, num_passes_b)

        factory = pass_factory(integer_passes(max_passes))
        group_a = factory.get(message, num_passes_a)
        group_a.reset()

        group_b = factory.get(message, num_passes_b)
        self.assertThat(
            group_a.passes[:min_passes],
            Equals(group_b.passes[:min_passes]),
        )

    def _test_disallowed_transition(self, num_passes, setup_op, invalid_op):
        """
        Assert that after some setup operation completes, another operation raises
        ``ValueError``.

        :param int num_passes: The number of passes to make available from the
            factory.

        :param (IPassGroup -> None) setup_op: Some initial operation to
            perform with the pass group.

        :param (IPassGroup -> None) invalid_op: Some follow-up operation to
            perform with the pass group and to assert raises an exception.
        """
        message = u"message"
        factory = pass_factory(integer_passes(num_passes))
        group = factory.get(message, num_passes)
        setup_op(group)
        self.assertThat(
            lambda: invalid_op(group),
            raises(ValueError),
        )

    @given(pass_counts(), sampled_from([reset, spend, invalidate]))
    def test_not_spendable(self, num_passes, setup_op):
        """
        ``PassGroup.mark_spent`` raises ``ValueError`` if any passes in the group
        are in a state other than in-use.
        """
        self._test_disallowed_transition(
            num_passes,
            setup_op,
            spend,
        )

    @given(pass_counts(), sampled_from([reset, spend, invalidate]))
    def test_not_resetable(self, num_passes, setup_op):
        """
        ``PassGroup.reset`` raises ``ValueError`` if any passes in the group are
        in a state other than in-use.
        """
        self._test_disallowed_transition(
            num_passes,
            setup_op,
            reset,
        )

    @given(pass_counts(), sampled_from([reset, spend, invalidate]))
    def test_not_invalidateable(self, num_passes, setup_op):
        """
        ``PassGroup.mark_invalid`` raises ``ValueError`` if any passes in the
        group are in a state other than in-use.
        """
        self._test_disallowed_transition(
            num_passes,
            setup_op,
            invalidate,
        )
