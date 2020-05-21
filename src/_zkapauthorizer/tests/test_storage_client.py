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
)

from twisted.internet.defer import (
    succeed,
    fail,
)

from .matchers import (
    even,
    odd,
)

from ..api import (
    MorePassesRequired,
)

from .._storage_client import (
    call_with_passes,
)
from .._storage_server import (
    _ValidationResult,
)

from .storage_common import (
    pass_factory,
)


def pass_counts():
    return integers(min_value=1, max_value=2 ** 8)


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
                partial(pass_factory().get, u"message"),
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
                partial(pass_factory().get, u"message"),
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
        passes = pass_factory()

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
        passes = pass_factory()

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
        passes = pass_factory()

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
        passes = pass_factory()

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
        passes = pass_factory()

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
