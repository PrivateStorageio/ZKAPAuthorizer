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

from functools import partial

from allmydata.client import config_from_string
from challenge_bypass_ristretto import random_signing_key
from hypothesis import given
from hypothesis.strategies import integers, sampled_from, sets
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    Equals,
    HasLength,
    Is,
    IsInstance,
    MatchesAll,
    MatchesStructure,
)
from testtools.twistedsupport import failed, succeeded
from twisted.internet.defer import fail, succeed

from .. import NAME
from .._storage_client import call_with_passes
from .._storage_server import _ValidationResult
from ..api import MorePassesRequired
from ..model import NotEnoughTokens
from ..spending import PassGroup
from ..storage_common import (
    get_configured_allowed_public_keys,
    get_configured_pass_value,
    get_configured_shares_needed,
    get_configured_shares_total,
)
from .matchers import raises
from .storage_common import pass_factory, privacypass_passes
from .strategies import dummy_ristretto_keys, pass_counts


class GetConfiguredValueTests(TestCase):
    """
    Tests for helpers for reading certain configuration values.
    """

    @given(integers(min_value=1, max_value=255))
    def test_get_configured_shares_needed(self, expected):
        """
        ``get_configured_shares_needed`` reads the ``shares.needed`` value from
        the ``client`` section as an integer.
        """
        config = config_from_string(
            "",
            "",
            """\
[client]
shares.needed = {}
shares.happy = 5
shares.total = 10
""".format(
                expected
            ),
        )

        self.assertThat(
            get_configured_shares_needed(config),
            Equals(expected),
        )

    @given(integers(min_value=1, max_value=255))
    def test_get_configured_shares_total(self, expected):
        """
        ``get_configured_shares_total`` reads the ``shares.total`` value from
        the ``client`` section as an integer.
        """
        config = config_from_string(
            "",
            "",
            """\
[client]
shares.needed = 5
shares.happy = 5
shares.total = {}
""".format(
                expected
            ),
        )

        self.assertThat(
            get_configured_shares_total(config),
            Equals(expected),
        )

    @given(integers(min_value=1, max_value=10000000))
    def test_get_configured_pass_value(self, expected):
        """
        ``get_configured_pass_value`` reads the ``pass-value`` value from the
        ``storageclient.plugins.privatestorageio-zkapauthz-v2`` section as an
        integer.
        """
        config = config_from_string(
            "",
            "",
            """\
[client]
shares.needed = 3
shares.happy = 5
shares.total = 10

[storageclient.plugins.{name}]
pass-value={pass_value}
""".format(
                name=NAME, pass_value=expected
            ),
        )

        self.assertThat(
            get_configured_pass_value(config),
            Equals(expected),
        )

    @given(sets(dummy_ristretto_keys(), min_size=1, max_size=10))
    def test_get_configured_allowed_public_keys(self, expected):
        """
        ``get_configured_pass_value`` reads the ``pass-value`` value from the
        ``storageclient.plugins.privatestorageio-zkapauthz-v2`` section as an
        integer.
        """
        config = config_from_string(
            "",
            "",
            """\
[client]
shares.needed = 3
shares.happy = 5
shares.total = 10

[storageclient.plugins.{name}]
allowed-public-keys = {allowed_public_keys}
""".format(
                name=NAME,
                allowed_public_keys=",".join(expected),
            ),
        )

        self.assertThat(
            get_configured_allowed_public_keys(config),
            Equals(expected),
        )


class CallWithPassesTests(TestCase):
    """
    Tests for ``call_with_passes``.
    """

    def setUp(self):
        super().setUp()
        self.signing_key = random_signing_key()

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
                partial(
                    pass_factory(privacypass_passes(self.signing_key, num_passes)).get,
                    b"message",
                ),
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
                partial(
                    pass_factory(privacypass_passes(self.signing_key, num_passes)).get,
                    b"message",
                ),
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
        passes = pass_factory(privacypass_passes(self.signing_key, num_passes))

        self.assertThat(
            call_with_passes(
                lambda group: succeed(group.passes),
                num_passes,
                partial(passes.get, b"message"),
            ),
            succeeded(
                AfterPreprocessing(
                    set,
                    Equals(
                        passes.issued_passes,
                    ),
                ),
            ),
        )

    @given(pass_counts())
    def test_passes_spent_on_success(self, num_passes):
        """
        ``call_with_passes`` marks the passes it uses as spent if the operation
        succeeds.
        """
        passes = pass_factory(privacypass_passes(self.signing_key, num_passes))

        self.assertThat(
            call_with_passes(
                lambda group: None,
                num_passes,
                partial(passes.get, b"message"),
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
        passes = pass_factory(privacypass_passes(self.signing_key, num_passes))

        self.assertThat(
            call_with_passes(
                lambda group: fail(Exception("Anything")),
                num_passes,
                partial(passes.get, b"message"),
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
        # We'll reject one pass from each of two calls so make sure we have
        # two more than necessary.
        reject_count = 2
        rejected_passes = set()
        passes = pass_factory(
            privacypass_passes(self.signing_key, num_passes + reject_count)
        )

        def maybe_reject_passes(group: PassGroup) -> None:
            if len(rejected_passes) < reject_count:
                # Reject the first pass
                rejected_passes.add(group.passes[0])

                # Signal the failure
                _ValidationResult(
                    valid=[pass_.preimage for pass_ in group.passes[1:]],
                    signature_check_failed=[0],
                ).raise_for(num_passes)
            else:
                # Otherwise accept them all.
                return None

        # To succeed with the given function, `call_with_passes` will have to
        # have to try (reject_count + 1) times and replace one rejected token
        # with a fresh one on each call after the first.
        self.assertThat(
            call_with_passes(
                maybe_reject_passes,
                num_passes,
                partial(passes.get, b"message"),
            ),
            succeeded(Always()),
        )
        self.assertThat(
            passes,
            MatchesStructure(
                returned=HasLength(0),
                in_use=HasLength(0),
                invalid_passes=MatchesAll(
                    HasLength(reject_count),
                    AfterPreprocessing(
                        lambda d: set(d.keys()), Equals(rejected_passes)
                    ),
                ),
                spent=HasLength(num_passes),
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
        passes = pass_factory(privacypass_passes(self.signing_key, num_passes))

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
                partial(passes.get, b"message"),
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
        passes = pass_factory(privacypass_passes(self.signing_key, num_passes + extras))
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
                partial(passes.get, b"message"),
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
                returned_passes=Equals(set(accepted)),
                in_use=HasLength(0),
                invalid_passes=AfterPreprocessing(
                    lambda invalid: set(invalid.keys()),
                    Equals(set(rejected)),
                ),
                spent=HasLength(0),
                issued_passes=Equals(set(accepted + rejected)),
            ),
        )


def reset(group):
    group.reset()


def spend(group):
    group.mark_spent()


def invalidate(group):
    group.mark_invalid("reason")


class PassFactoryTests(TestCase):
    """
    Tests for ``pass_factory``.

    It is unfortunate that this isn't the same test suite as
    ``test_spending.PassGroupTests``.
    """

    def setUp(self):
        super().setUp()
        self.signing_key = random_signing_key()

    @given(pass_counts(), pass_counts())
    def test_returned_passes_reused(self, num_passes_a, num_passes_b):
        """
        ``IPassGroup.reset`` makes passes available to be returned by
        ``IPassGroup.get`` again.
        """
        message = b"message"
        min_passes = min(num_passes_a, num_passes_b)
        max_passes = max(num_passes_a, num_passes_b)

        factory = pass_factory(privacypass_passes(self.signing_key, max_passes))
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
        message = b"message"
        factory = pass_factory(privacypass_passes(self.signing_key, num_passes))
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
