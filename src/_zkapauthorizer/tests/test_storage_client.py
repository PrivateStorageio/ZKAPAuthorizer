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

import attr

from itertools import (
    count,
    islice,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    Always,
    Is,
    Equals,
    AfterPreprocessing,
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

from ..api import (
    MorePassesRequired,
)

from .._storage_client import (
    call_with_passes,
)
from .._storage_server import (
    _ValidationResult,
)

def pass_counts():
    return integers(min_value=1, max_value=2 ** 8)


def pass_factory():
    return _PassFactory()

@attr.s
class _PassFactory(object):
    """
    A stateful pass issuer.

    :ivar list spent: All of the passes ever issued.

    :ivar _fountain: A counter for making each new pass issued unique.
    """
    spent = attr.ib(default=attr.Factory(list))

    _fountain = attr.ib(default=attr.Factory(count))

    def get(self, num_passes):
        passes = list(islice(self._fountain, num_passes))
        self.spent.extend(passes)
        return passes


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
                lambda passes: succeed(result),
                num_passes,
                pass_factory().get,
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
                lambda passes: fail(result),
                num_passes,
                pass_factory().get,
            ),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    Is(result),
                ),
            ),
        )

    @given(pass_counts())
    def test_passes(self, num_passes):
        """
        ``call_with_passes`` calls the given method with a list of passes
        containing ``num_passes`` created by the function passed for
        ``get_passes``.
        """
        passes = pass_factory()

        self.assertThat(
            call_with_passes(
                lambda passes: succeed(passes),
                num_passes,
                passes.get,
            ),
            succeeded(
                Equals(
                    passes.spent,
                ),
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

        def reject_even_pass_values(passes):
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
                passes.get,
            ),
            succeeded(Always()),
        )

    @given(pass_counts())
    def test_pass_through_too_few_passes(self, num_passes):
        """
        ``call_with_passes`` lets ``MorePassesRequired`` propagate through it if
        no passes have been marked as invalid.  This happens if all passes
        given were valid but too fewer were given.
        """
        passes = pass_factory()

        def reject_passes(passes):
            _ValidationResult(
                valid=range(len(passes)),
                signature_check_failed=[],
            ).raise_for(len(passes) + 1)

        self.assertThat(
            call_with_passes(
                reject_passes,
                num_passes,
                passes.get,
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
