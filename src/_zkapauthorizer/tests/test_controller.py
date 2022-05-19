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
Tests for ``_zkapauthorizer.controller``.
"""

from datetime import datetime, timedelta, timezone
from functools import partial
from json import loads
from typing import Callable

import attr
from challenge_bypass_ristretto import (
    BatchDLEQProof,
    BlindedToken,
    PublicKey,
    SecurityException,
    TokenPreimage,
    VerificationSignature,
    random_signing_key,
)
from hypothesis import assume, given
from hypothesis.strategies import integers, lists, randoms, sampled_from
from testtools import TestCase
from testtools.content import text_content
from testtools.matchers import (
    AfterPreprocessing,
    AllMatch,
    Always,
    Equals,
    HasLength,
    Is,
    IsInstance,
    MatchesAll,
    MatchesStructure,
)
from testtools.twistedsupport import failed, has_no_result, succeeded
from treq.testing import StubTreq
from twisted.internet.defer import fail, succeed
from twisted.internet.interfaces import IReactorTime
from twisted.internet.task import Clock
from twisted.python.url import URL
from twisted.web.http import BAD_REQUEST, INTERNAL_SERVER_ERROR, UNSUPPORTED_MEDIA_TYPE
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgent
from twisted.web.resource import ErrorPage, Resource
from zope.interface import implementer

from .._json import dumps_utf8
from ..controller import (
    AlreadySpent,
    DoubleSpendRedeemer,
    DummyRedeemer,
    ErrorRedeemer,
    IndexedRedeemer,
    IRedeemer,
    NonRedeemer,
    PaymentController,
    RecordingRedeemer,
    RistrettoRedeemer,
    UnexpectedResponse,
    Unpaid,
    UnpaidRedeemer,
    UnrecognizedFailureReason,
    bracket,
    token_count_for_group,
)
from ..model import DoubleSpend as model_DoubleSpend
from ..model import Error as model_Error
from ..model import Pass
from ..model import Pending as model_Pending
from ..model import Redeemed as model_Redeemed
from ..model import Redeeming as model_Redeeming
from ..model import UnblindedToken
from ..model import Unpaid as model_Unpaid
from .fixtures import TemporaryVoucherStore
from .matchers import Provides, between, raises
from .strategies import (
    aware_datetimes,
    clocks,
    dummy_ristretto_keys,
    redemption_group_counts,
    tahoe_configs,
    voucher_counters,
    voucher_objects,
    vouchers,
)


def clock_to_now(clock: IReactorTime) -> Callable[[], datetime]:
    """
    :return: A function which returns a timezone-aware UTC datetime
        representing the time of ``clock`` at the time of each call.
    """

    def now():
        s = clock.seconds()
        d = datetime.utcfromtimestamp(s)
        return d.replace(tzinfo=timezone.utc)

    return now


class TokenCountForGroupTests(TestCase):
    """
    Tests for ``token_count_for_group``.
    """

    @given(
        integers(),
        integers(),
        integers(),
    )
    def test_out_of_bounds(self, num_groups, total_tokens, group_number):
        """
        If there are not enough tokens so that each group gets at least one or if
        the indicated group number does properly identify a group from the
        range then ``ValueError`` is raised.
        """
        assume(
            group_number < 0 or group_number >= num_groups or total_tokens < num_groups
        )
        self.assertThat(
            lambda: token_count_for_group(num_groups, total_tokens, group_number),
            raises(ValueError),
        )

    @given(
        redemption_group_counts(),
        integers(min_value=0),
    )
    def test_sum(self, num_groups, extra_tokens):
        """
        The sum of the token count for all groups equals the requested total
        tokens.
        """
        total_tokens = num_groups + extra_tokens
        self.assertThat(
            sum(
                token_count_for_group(num_groups, total_tokens, group_number)
                for group_number in range(num_groups)
            ),
            Equals(total_tokens),
        )

    @given(
        redemption_group_counts(),
        integers(min_value=0),
    )
    def test_well_distributed(self, num_groups, extra_tokens):
        """
        Tokens are distributed roughly evenly across all group numbers.
        """
        total_tokens = num_groups + extra_tokens

        lower_bound = total_tokens // num_groups
        upper_bound = total_tokens // num_groups + 1

        self.assertThat(
            list(
                token_count_for_group(num_groups, total_tokens, group_number)
                for group_number in range(num_groups)
            ),
            AllMatch(between(lower_bound, upper_bound)),
        )


class PaymentControllerTests(TestCase):
    """
    Tests for ``PaymentController``.
    """

    @given(tahoe_configs(), aware_datetimes(), vouchers(), dummy_ristretto_keys())
    def test_should_not_redeem(self, get_config, now, voucher, public_key):
        """
        ``PaymentController.redeem`` raises ``ValueError`` if passed a voucher in
        a state when redemption should not be started.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        controller = PaymentController(
            store,
            DummyRedeemer(public_key),
            default_token_count=100,
            allowed_public_keys={public_key},
            clock=Clock(),
        )

        self.assertThat(
            controller.redeem(voucher),
            succeeded(Always()),
        )

        # Sanity check.  It should be redeemed now.
        voucher_obj = controller.get_voucher(voucher)
        self.assertThat(
            voucher_obj.state.should_start_redemption(),
            Equals(False),
        )

        self.assertThat(
            controller.redeem(voucher),
            failed(
                AfterPreprocessing(
                    lambda f: f.type,
                    Equals(ValueError),
                ),
            ),
        )

    @given(tahoe_configs(), aware_datetimes(), vouchers())
    def test_not_redeemed_while_redeeming(self, get_config, now, voucher):
        """
        A ``Voucher`` is not marked redeemed before ``IRedeemer.redeem``
        completes.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        controller = PaymentController(
            store,
            NonRedeemer(),
            default_token_count=100,
            allowed_public_keys=set(),
            clock=Clock(),
        )
        self.assertThat(
            controller.redeem(voucher),
            has_no_result(),
        )

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher.state,
            Equals(model_Pending(counter=0)),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
        voucher_counters(),
        dummy_ristretto_keys(),
    )
    def test_redeeming(self, get_config, now, voucher, num_successes, public_key):
        """
        A ``Voucher`` is marked redeeming while ``IRedeemer.redeem`` is actively
        working on redeeming it with a counter value that reflects the number
        of successful partial redemptions so far completed.
        """
        # The voucher counter can be zero (no tries yet succeeded).  We want
        # at least *one* run through so we'll bump this up to be sure we get
        # that.
        counter = num_successes + 1
        redeemer = IndexedRedeemer(
            [DummyRedeemer(public_key)] * num_successes + [NonRedeemer()],
        )
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        controller = PaymentController(
            store,
            redeemer,
            # This will give us one ZKAP per attempt.
            default_token_count=counter,
            # Require more success than we're going to get so it doesn't
            # finish.
            num_redemption_groups=counter,
            allowed_public_keys={public_key},
            clock=Clock(),
        )

        self.assertThat(
            controller.redeem(voucher),
            has_no_result(),
        )

        controller_voucher = controller.get_voucher(voucher)
        self.assertThat(
            controller_voucher.state,
            Equals(
                model_Redeeming(
                    started=now,
                    counter=num_successes,
                )
            ),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
        voucher_counters(),
        voucher_counters().map(lambda v: v + 1),
        dummy_ristretto_keys(),
    )
    def test_restart_redeeming(
        self, get_config, now, voucher, before_restart, after_restart, public_key
    ):
        """
        If some redemption groups for a voucher have succeeded but the process is
        interrupted, redemption begins at the first incomplete redemption
        group when it resumes.

        :parm int before_restart: The number of redemption groups which will
            be allowed to succeed before making the redeemer hang.  Redemption
            will then be required to begin again from only database state.

        :param int after_restart: The number of redemption groups which will
            be required to succeed after restarting the process.
        """
        # Divide redemption into some groups that will succeed before a
        # restart and some that must succeed after a restart.
        num_redemption_groups = before_restart + after_restart
        # Give it enough tokens so each group can have one.
        num_tokens = num_redemption_groups

        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store

        def first_try():
            controller = PaymentController(
                store,
                # It will let `before_restart` attempts succeed before hanging.
                IndexedRedeemer(
                    [DummyRedeemer(public_key)] * before_restart
                    + [NonRedeemer()] * after_restart,
                ),
                default_token_count=num_tokens,
                num_redemption_groups=num_redemption_groups,
                allowed_public_keys={public_key},
                clock=Clock(),
            )
            self.assertThat(
                controller.redeem(voucher),
                has_no_result(),
            )

        def second_try():
            # The controller will find the voucher in the voucher store and
            # restart redemption on its own.
            return PaymentController(
                store,
                # It will succeed only for the higher counter values which did
                # not succeed or did not get started on the first try.
                IndexedRedeemer(
                    [NonRedeemer()] * before_restart
                    + [DummyRedeemer(public_key)] * after_restart,
                ),
                # The default token count for this new controller doesn't
                # matter.  The redemption attempt already started with some
                # token count.  That token count must be respected on
                # resumption.
                default_token_count=0,
                # The number of redemption groups must not change for
                # redemption of a particular voucher.
                num_redemption_groups=num_redemption_groups,
                allowed_public_keys={public_key},
                clock=Clock(),
            )

        first_try()
        controller = second_try()

        persisted_voucher = controller.get_voucher(voucher)
        self.assertThat(
            persisted_voucher.state,
            Equals(
                model_Redeemed(
                    finished=now,
                    token_count=num_tokens,
                ),
            ),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
        voucher_counters(),
        integers(min_value=0, max_value=100),
    )
    def test_stop_redeeming_on_error(
        self, get_config, now, voucher, counter, extra_tokens
    ):
        """
        If an error is encountered on one of the redemption attempts performed by
        ``IRedeemer.redeem``, the effort is suspended until the normal retry
        logic activates.
        """
        num_redemption_groups = counter + 1
        num_tokens = num_redemption_groups + extra_tokens
        redeemer = RecordingRedeemer(UnpaidRedeemer())

        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        controller = PaymentController(
            store,
            redeemer,
            default_token_count=num_tokens,
            num_redemption_groups=num_redemption_groups,
            allowed_public_keys=set(),
            clock=Clock(),
        )
        self.assertThat(
            controller.redeem(voucher),
            succeeded(Always()),
        )
        self.assertThat(
            redeemer.redemptions,
            AfterPreprocessing(
                len,
                Equals(1),
            ),
        )

    @given(tahoe_configs(), dummy_ristretto_keys(), aware_datetimes(), vouchers())
    def test_redeemed_after_redeeming(self, get_config, public_key, now, voucher):
        """
        A ``Voucher`` is marked as redeemed after ``IRedeemer.redeem`` succeeds.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        controller = PaymentController(
            store,
            DummyRedeemer(public_key),
            default_token_count=100,
            allowed_public_keys={public_key},
            clock=Clock(),
        )
        self.assertThat(
            controller.redeem(voucher),
            succeeded(Always()),
        )

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher.state,
            Equals(
                model_Redeemed(
                    finished=now,
                    token_count=100,
                )
            ),
        )

    @given(
        tahoe_configs(),
        aware_datetimes(),
        vouchers(),
    )
    def test_error_state(self, get_config, now, voucher):
        """
        If ``IRedeemer.redeem`` fails with an unrecognized exception then the
        voucher is put into the error state.
        """
        details = "these are the reasons it broke"
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        controller = PaymentController(
            store,
            ErrorRedeemer(details),
            default_token_count=100,
            allowed_public_keys=set(),
            clock=Clock(),
        )
        self.assertThat(
            controller.redeem(voucher),
            succeeded(Always()),
        )

        persisted_voucher = controller.get_voucher(voucher)
        self.assertThat(
            persisted_voucher,
            MatchesStructure(
                state=Equals(
                    model_Error(
                        finished=now,
                        details=details,
                    )
                ),
            ),
        )

    @given(tahoe_configs(), aware_datetimes(), vouchers())
    def test_double_spent_after_double_spend(self, get_config, now, voucher):
        """
        A ``Voucher`` is marked as double-spent after ``IRedeemer.redeem`` fails
        with ``AlreadySpent``.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        controller = PaymentController(
            store,
            DoubleSpendRedeemer(),
            default_token_count=100,
            allowed_public_keys=set(),
            clock=Clock(),
        )
        self.assertThat(
            controller.redeem(voucher),
            succeeded(Always()),
        )

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher,
            MatchesStructure(
                state=Equals(
                    model_DoubleSpend(
                        finished=now,
                    )
                ),
            ),
        )

    @given(tahoe_configs(), aware_datetimes(), vouchers(), dummy_ristretto_keys())
    def test_redeem_pending_on_startup(self, get_config, now, voucher, public_key):
        """
        When ``PaymentController`` is created, any vouchers in the store in the
        pending state are redeemed.
        """
        store = self.useFixture(TemporaryVoucherStore(lambda: now, get_config)).store
        # Create the voucher state in the store with a redemption that will
        # certainly fail.
        unpaid_controller = PaymentController(
            store,
            UnpaidRedeemer(),
            default_token_count=100,
            allowed_public_keys=set(),
            clock=Clock(),
        )
        self.assertThat(
            unpaid_controller.redeem(voucher),
            succeeded(Always()),
        )

        # Make sure we got where we wanted.
        self.assertThat(
            unpaid_controller.get_voucher(voucher).state,
            IsInstance(model_Unpaid),
        )

        # Create another controller with the same store.  It will see the
        # voucher state and attempt a redemption on its own.  It has I/O as an
        # `__init__` side-effect. :/
        success_controller = PaymentController(
            store,
            DummyRedeemer(public_key),
            default_token_count=100,
            allowed_public_keys={public_key},
            clock=Clock(),
        )

        self.assertThat(
            success_controller.get_voucher(voucher).state,
            IsInstance(model_Redeemed),
        )

    @given(
        tahoe_configs(),
        clocks(),
        vouchers(),
    )
    def test_redeem_error_after_delay(self, get_config, clock, voucher):
        """
        When ``PaymentController`` receives a non-terminal error trying to redeem
        a voucher, after some time passes it tries to redeem the voucher
        again.
        """
        datetime_now = clock_to_now(clock)
        store = self.useFixture(
            TemporaryVoucherStore(
                datetime_now,
                get_config,
            ),
        ).store
        controller = PaymentController(
            store,
            UnpaidRedeemer(),
            default_token_count=100,
            allowed_public_keys=set(),
            clock=clock,
        )
        self.assertThat(
            controller.redeem(voucher),
            succeeded(Always()),
        )
        # It fails this time.
        self.assertThat(
            controller.get_voucher(voucher).state,
            MatchesAll(
                IsInstance(model_Unpaid),
                MatchesStructure(
                    finished=Equals(datetime_now()),
                ),
            ),
        )

        # Some time passes.
        interval = timedelta(hours=1)
        clock.advance(interval.total_seconds())

        # It failed again.
        self.assertThat(
            controller.get_voucher(voucher).state,
            MatchesAll(
                IsInstance(model_Unpaid),
                MatchesStructure(
                    # At the new time, demonstrating the retry was performed.
                    finished=Equals(datetime_now()),
                ),
            ),
        )

    @given(
        # Get a random object so we can shuffle allowed and disallowed keys
        # together in an unpredictable but Hypothesis-deterministicway.
        randoms(),
        # Control time just to control it.  Nothing particularly interesting
        # relating to time happens in this test.
        clocks(),
        # Build a voucher number to use with the attempted redemption.
        vouchers(),
        # Build a number of redemption groups.
        integers(min_value=1, max_value=16).flatmap(
            # Build a number of groups to have an allowed key
            lambda num_groups: integers(min_value=0, max_value=num_groups).flatmap(
                # Build distinct public keys
                lambda num_allowed_key_groups: lists(
                    dummy_ristretto_keys(),
                    min_size=num_groups,
                    max_size=num_groups,
                    unique=True,
                ).map(
                    # Split the keys into allowed and disallowed groups
                    lambda public_keys: (
                        public_keys[:num_allowed_key_groups],
                        public_keys[num_allowed_key_groups:],
                    ),
                ),
            ),
        ),
        # Build a number of extra tokens to request beyond the minimum number
        # required by the number of redemption groups we have.
        integers(min_value=0, max_value=32),
    )
    def test_sequester_tokens_for_untrusted_key(
        self, random, clock, voucher, public_keys, extra_token_count
    ):
        """
        All unblinded tokens which are returned from the redemption process
        associated with a public key that the controller has not been
        configured to trust are not made available to be spent.  The
        corresponding voucher still reaches the redeemed state but with the
        number of sequestered tokens subtracted from its ``token_count``.
        """
        # The controller will be configured to allow one group of keys but not
        # the other.
        allowed_public_keys, disallowed_public_keys = public_keys
        all_public_keys = allowed_public_keys + disallowed_public_keys

        # Compute the total number of tokens we'll request, spread across all
        # redemption groups.
        token_count = len(all_public_keys) + extra_token_count

        # Mix them up so they're not always presented to the controller in the
        # same order - and in particular so they're not always presented such
        # that all allowed keys come before all disallowed keys.
        random.shuffle(all_public_keys)

        # Redeem the voucher in enough groups so that each key can be
        # presented once.
        num_redemption_groups = len(all_public_keys)

        datetime_now = clock_to_now(clock)
        store = self.useFixture(TemporaryVoucherStore(datetime_now)).store

        redeemers = list(DummyRedeemer(public_key) for public_key in all_public_keys)

        controller = PaymentController(
            store,
            IndexedRedeemer(redeemers),
            default_token_count=token_count,
            num_redemption_groups=num_redemption_groups,
            allowed_public_keys=set(allowed_public_keys),
            clock=clock,
        )

        # Even with disallowed public keys, the *redemption* is considered
        # successful.
        self.assertThat(
            controller.redeem(voucher),
            succeeded(Always()),
        )

        def count_in_group(public_keys, key_group):
            return sum(
                (
                    token_count_for_group(num_redemption_groups, token_count, n)
                    for n, public_key in enumerate(public_keys)
                    if public_key in key_group
                ),
                0,
            )

        allowed_token_count = count_in_group(all_public_keys, allowed_public_keys)
        disallowed_token_count = count_in_group(all_public_keys, disallowed_public_keys)

        # As a sanity check: allowed + disallowed should equal total or we've
        # screwed up the test logic.
        self.assertThat(
            allowed_token_count + disallowed_token_count,
            Equals(token_count),
        )

        # The counts on the voucher object should reflect what was allowed and
        # what was disallowed.
        self.expectThat(
            store.get(voucher),
            MatchesStructure(
                expected_tokens=Equals(token_count),
                state=Equals(
                    model_Redeemed(
                        finished=datetime_now(),
                        token_count=allowed_token_count,
                    ),
                ),
            ),
        )

        # Also the actual number of tokens available should agree.
        self.expectThat(
            store.count_unblinded_tokens(),
            Equals(allowed_token_count),
        )

        # And finally only tokens from the groups using an allowed key should
        # be made available to be spent.
        voucher_obj = store.get(voucher)
        allowed_tokens = list(
            unblinded_token
            for counter, redeemer in enumerate(redeemers)
            if redeemer._public_key in allowed_public_keys
            for unblinded_token in redeemer.redeemWithCounter(
                voucher_obj,
                counter,
                redeemer.random_tokens_for_voucher(
                    voucher_obj,
                    counter,
                    token_count_for_group(
                        num_redemption_groups,
                        token_count,
                        counter,
                    ),
                ),
            ).result.unblinded_tokens
        )
        self.expectThat(
            store.get_unblinded_tokens(store.count_unblinded_tokens()),
            Equals(allowed_tokens),
        )


NOWHERE = URL.from_text("https://127.0.0.1/")


class RistrettoRedeemerTests(TestCase):
    """
    Tests for ``RistrettoRedeemer``.
    """

    def test_interface(self):
        """
        An ``RistrettoRedeemer`` instance provides ``IRedeemer``.
        """
        redeemer = RistrettoRedeemer(stub_agent(), NOWHERE)
        self.assertThat(
            redeemer,
            Provides([IRedeemer]),
        )

    @given(voucher_objects(), voucher_counters(), integers(min_value=1, max_value=100))
    def test_good_ristretto_redemption(self, voucher, counter, num_tokens):
        """
        If the issuer returns a successful result then
        ``RistrettoRedeemer.redeem`` returns a ``Deferred`` that fires with a
        list of ``UnblindedToken`` instances.
        """
        signing_key = random_signing_key()
        issuer = RistrettoRedemption(signing_key)
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, counter, num_tokens)
        d = redeemer.redeemWithCounter(
            voucher,
            counter,
            random_tokens,
        )
        self.assertThat(
            d,
            succeeded(
                MatchesStructure(
                    unblinded_tokens=MatchesAll(
                        AllMatch(
                            IsInstance(UnblindedToken),
                        ),
                        HasLength(num_tokens),
                    ),
                    public_key=Equals(
                        PublicKey.from_signing_key(signing_key)
                        .encode_base64()
                        .decode("utf-8"),
                    ),
                ),
            ),
        )

    @given(voucher_objects(), voucher_counters(), integers(min_value=0, max_value=100))
    def test_non_json_response(self, voucher, counter, num_tokens):
        """
        If the issuer responds with something that isn't JSON then the response is
        logged and the ``Deferred`` fires with a ``Failure`` wrapping
        ``UnexpectedResponse``.
        """
        issuer = UnexpectedResponseRedemption()
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, counter, num_tokens)

        d = redeemer.redeemWithCounter(
            voucher,
            counter,
            random_tokens,
        )

        self.assertThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    Equals(
                        UnexpectedResponse(
                            INTERNAL_SERVER_ERROR,
                            b"Sorry, this server does not behave well.",
                        ),
                    ),
                ),
            ),
        )

    @given(voucher_objects(), voucher_counters(), integers(min_value=0, max_value=100))
    def test_redemption_denied_alreadyspent(self, voucher, counter, extra_tokens):
        """
        If the issuer declines to allow the voucher to be redeemed and gives a
        reason that the voucher has already been spent, ``RistrettoRedeem``
        returns a ``Deferred`` that fires with a ``Failure`` wrapping
        ``AlreadySpent``.
        """
        num_tokens = counter + extra_tokens
        issuer = already_spent_redemption()
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, counter, num_tokens)
        d = redeemer.redeemWithCounter(
            voucher,
            counter,
            random_tokens,
        )
        self.assertThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(AlreadySpent),
                ),
            ),
        )

    @given(voucher_objects(), voucher_counters(), integers(min_value=0, max_value=100))
    def test_redemption_denied_unpaid(self, voucher, counter, extra_tokens):
        """
        If the issuer declines to allow the voucher to be redeemed and gives a
        reason that the voucher has not been paid for, ``RistrettoRedeem``
        returns a ``Deferred`` that fires with a ``Failure`` wrapping
        ``Unpaid``.
        """
        num_tokens = counter + extra_tokens
        issuer = unpaid_redemption()
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, counter, num_tokens)
        d = redeemer.redeemWithCounter(
            voucher,
            counter,
            random_tokens,
        )
        self.assertThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(Unpaid),
                ),
            ),
        )

    @given(voucher_objects(), voucher_counters(), integers(min_value=0, max_value=100))
    def test_redemption_unknown_response(self, voucher, counter, extra_tokens):
        """
        If the issuer returns a failure without a recognizable reason then
        ``RistrettoRedeemer.redeemWithCounter`` returns a ``Deferred`` that
        fails with ``UnrecognizedFailureReason``.
        """
        details = "mysterious"
        num_tokens = counter + extra_tokens
        issuer = UnsuccessfulRedemption(details)
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, counter, num_tokens)
        d = redeemer.redeemWithCounter(
            voucher,
            counter,
            random_tokens,
        )
        self.assertThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    Equals(
                        UnrecognizedFailureReason(
                            {
                                "success": False,
                                "reason": details,
                            }
                        )
                    ),
                ),
            ),
        )

    @given(voucher_objects(), voucher_counters(), integers(min_value=0, max_value=100))
    def test_bad_ristretto_redemption(self, voucher, counter, extra_tokens):
        """
        If the issuer returns a successful result with an invalid proof then
        ``RistrettoRedeemer.redeem`` returns a ``Deferred`` that fires with a
        ``Failure`` wrapping ``SecurityException``.
        """
        num_tokens = counter + extra_tokens
        signing_key = random_signing_key()
        issuer = RistrettoRedemption(signing_key)

        # Make it lie about the public key it is using.  This causes the proof
        # to be invalid since it proves the signature was made with a
        # different key than reported in the response.
        issuer.public_key = PublicKey.from_signing_key(random_signing_key())

        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)
        random_tokens = redeemer.random_tokens_for_voucher(voucher, counter, num_tokens)
        d = redeemer.redeemWithCounter(
            voucher,
            counter,
            random_tokens,
        )
        self.addDetail("redeem Deferred", text_content(str(d)))
        self.assertThat(
            d,
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(SecurityException),
                ),
            ),
        )

    @given(voucher_objects(), voucher_counters(), integers(min_value=0, max_value=100))
    def test_ristretto_pass_construction(self, voucher, counter, extra_tokens):
        """
        The passes constructed using unblinded tokens and messages pass the
        Ristretto verification check.
        """
        num_tokens = counter + extra_tokens
        message = b"hello world"
        signing_key = random_signing_key()
        issuer = RistrettoRedemption(signing_key)
        treq = treq_for_loopback_ristretto(issuer)
        redeemer = RistrettoRedeemer(treq, NOWHERE)

        random_tokens = redeemer.random_tokens_for_voucher(voucher, counter, num_tokens)
        d = redeemer.redeemWithCounter(
            voucher,
            counter,
            random_tokens,
        )

        def unblinded_tokens_to_passes(result):
            passes = redeemer.tokens_to_passes(message, result.unblinded_tokens)
            return passes

        d.addCallback(unblinded_tokens_to_passes)

        self.assertThat(
            d,
            succeeded(
                AfterPreprocessing(
                    partial(ristretto_verify, signing_key, message),
                    Equals(True),
                ),
            ),
        )


def ristretto_verify(signing_key, message, marshaled_passes):
    """
    Verify that the given passes were generated in a process that involved a
    signature from the given signing key and using the given message.

    :param SigningKey signing_key: A signing key which should have signed some
        random blinded tokens earlier in the lifecycle of the passes to
        verify.

    :param bytes message: Request binding data which is involved in the
        generation of the passes to verify.

    :param list[bytes] marshaled_passes: Token preimages and corresponding
        message signatures to verify.  Each element contains two
        space-separated base64 encoded values, the first representing the
        preimage and the second representing the signature.

    :return bool: ``True`` if and only if all of the passes represented by
        ``marshaled_passes`` pass the Ristretto-defined verification for an
        exchange using the given signing key and message.
    """

    def decode(marshaled_pass):
        pass_ = Pass.from_bytes(marshaled_pass)
        return (
            TokenPreimage.decode_base64(pass_.preimage),
            VerificationSignature.decode_base64(pass_.signature),
        )

    servers_passes = list(
        decode(marshaled_pass.pass_bytes) for marshaled_pass in marshaled_passes
    )
    servers_unblinded_tokens = list(
        signing_key.rederive_unblinded_token(token_preimage)
        for (token_preimage, sig) in servers_passes
    )
    servers_verification_sigs = list(sig for (token_preimage, sig) in servers_passes)
    servers_verification_keys = list(
        unblinded_token.derive_verification_key_sha512()
        for unblinded_token in servers_unblinded_tokens
    )
    invalid_passes = list(
        key.invalid_sha512(
            sig,
            message,
        )
        for (key, sig) in zip(servers_verification_keys, servers_verification_sigs)
    )

    return not any(invalid_passes)


def treq_for_loopback_ristretto(local_issuer):
    """
    Create a ``treq``-alike which can dispatch to a local issuer.
    """
    v1 = Resource()
    v1.putChild(b"redeem", local_issuer)
    root = Resource()
    root.putChild(b"v1", v1)
    return StubTreq(root)


@implementer(IAgent)
class _StubAgent(object):
    def request(self, method, uri, headers=None, bodyProducer=None):
        return fail(Exception("It's only a model."))


def stub_agent():
    return _StubAgent()


class UnexpectedResponseRedemption(Resource):
    """
    An ``UnexpectedResponseRedemption`` simulates the Ristretto redemption
    server but always returns a non-JSON error response.
    """

    def render_POST(self, request):
        request.setResponseCode(INTERNAL_SERVER_ERROR)
        return b"Sorry, this server does not behave well."


@attr.s
class UnsuccessfulRedemption(Resource, object):
    """
    A fake redemption server which always returns an unsuccessful response.

    :ivar unicode reason: The value for the ``reason`` field of the result.
    """

    reason = attr.ib()

    def __attrs_post_init__(self):
        Resource.__init__(self)

    def render_POST(self, request):
        request_error = check_redemption_request(request)
        if request_error is not None:
            return request_error

        return bad_request(request, {"success": False, "reason": self.reason})


def unpaid_redemption():
    """
    Return a fake Ristretto redemption server which always refuses to allow
    vouchers to be redeemed and reports an error that the voucher has not been
    paid for.
    """
    return UnsuccessfulRedemption("unpaid")


def already_spent_redemption():
    """
    Return a fake Ristretto redemption server which always refuses to allow
    vouchers to be redeemed and reports an error that the voucher has already
    been redeemed.
    """
    return UnsuccessfulRedemption("double-spend")


class RistrettoRedemption(Resource):
    def __init__(self, signing_key):
        Resource.__init__(self)
        self.signing_key = signing_key
        self.public_key = PublicKey.from_signing_key(signing_key)

    def render_POST(self, request):
        request_error = check_redemption_request(request)
        if request_error is not None:
            return request_error

        request_body = loads(request.content.read())
        marshaled_blinded_tokens = request_body["redeemTokens"]
        servers_blinded_tokens = list(
            BlindedToken.decode_base64(marshaled_blinded_token.encode("ascii"))
            for marshaled_blinded_token in marshaled_blinded_tokens
        )
        servers_signed_tokens = list(
            self.signing_key.sign(blinded_token)
            for blinded_token in servers_blinded_tokens
        )
        marshaled_signed_tokens = list(
            signed_token.encode_base64() for signed_token in servers_signed_tokens
        )
        servers_proof = BatchDLEQProof.create(
            self.signing_key,
            servers_blinded_tokens,
            servers_signed_tokens,
        )
        try:
            marshaled_proof = servers_proof.encode_base64()
        finally:
            servers_proof.destroy()

        return dumps_utf8(
            {
                "success": True,
                "public-key": self.public_key.encode_base64().decode("utf-8"),
                "signatures": list(t.decode("utf-8") for t in marshaled_signed_tokens),
                "proof": marshaled_proof.decode("utf-8"),
            }
        )


class CheckRedemptionRequestTests(TestCase):
    """
    Tests for ``check_redemption_request``.
    """

    def test_content_type(self):
        """
        If the request content-type is not application/json, the response is
        **Unsupported Media Type**.
        """
        issuer = unpaid_redemption()
        treq = treq_for_loopback_ristretto(issuer)
        d = treq.post(
            NOWHERE.child("v1", "redeem").to_text().encode("ascii"),
            b"{}",
        )
        self.assertThat(
            d,
            succeeded(
                AfterPreprocessing(
                    lambda response: response.code,
                    Equals(UNSUPPORTED_MEDIA_TYPE),
                ),
            ),
        )

    def test_not_json(self):
        """
        If the request body cannot be decoded as json, the response is **Bad
        Request**.
        """
        issuer = unpaid_redemption()
        treq = treq_for_loopback_ristretto(issuer)
        d = treq.post(
            NOWHERE.child("v1", "redeem").to_text().encode("ascii"),
            b"foo",
            headers=Headers({"content-type": ["application/json"]}),
        )
        self.assertThat(
            d,
            succeeded(
                AfterPreprocessing(
                    lambda response: response.code,
                    Equals(BAD_REQUEST),
                ),
            ),
        )

    @given(
        lists(
            sampled_from(
                ["redeemVoucher", "redeemCounter", "redeemTokens"],
            ),
            # Something must be missing if the length is no longer than 2
            # because there are 3 required properties.
            max_size=2,
            unique=True,
        ),
    )
    def test_missing_properties(self, properties):
        """
        If the JSON object in the request body does not include all the necessary
        properties, the response is **Bad Request**.
        """
        issuer = unpaid_redemption()
        treq = treq_for_loopback_ristretto(issuer)
        d = treq.post(
            NOWHERE.child("v1", "redeem").to_text().encode("ascii"),
            dumps_utf8(dict.fromkeys(properties)),
            headers=Headers({"content-type": ["application/json"]}),
        )
        self.assertThat(
            d,
            succeeded(
                AfterPreprocessing(
                    lambda response: response.code,
                    Equals(BAD_REQUEST),
                ),
            ),
        )


def check_redemption_request(request):
    """
    Verify that the given request conforms to the redemption server's public
    interface.
    """
    if request.requestHeaders.getRawHeaders(b"content-type") != [b"application/json"]:
        return bad_content_type(request)

    p = request.content.tell()
    content = request.content.read()
    request.content.seek(p)

    try:
        request_body = loads(content)
    except ValueError:
        return bad_request(request, None)

    expected_keys = {"redeemVoucher", "redeemCounter", "redeemTokens"}
    actual_keys = set(request_body.keys())
    if expected_keys != actual_keys:
        return bad_request(
            request,
            {
                "success": False,
                "reason": "{} != {}".format(
                    expected_keys,
                    actual_keys,
                ),
            },
        )
    return None


def bad_request(request, body_object):
    request.setResponseCode(BAD_REQUEST)
    request.setHeader(b"content-type", b"application/json")
    request.write(dumps_utf8(body_object))
    return b""


def bad_content_type(request):
    return ErrorPage(
        UNSUPPORTED_MEDIA_TYPE,
        b"Unsupported media type",
        b"Unsupported media type",
    ).render(request)


class _BracketTestMixin:
    """
    Tests for ``bracket``.
    """

    def wrap_success(self, result):
        raise NotImplementedError()

    def wrap_failure(self, result):
        raise NotImplementedError()

    def test_success(self):
        """
        ``bracket`` calls ``first`` then ``between`` then ``last`` and returns a
        ``Deferred`` that fires with the result of ``between``.
        """
        result = object()
        actions = []
        first = partial(actions.append, "first")

        def between():
            actions.append("between")
            return self.wrap_success(result)

        last = partial(actions.append, "last")
        self.assertThat(
            bracket(first, last, between),
            succeeded(
                Is(result),
            ),
        )
        self.assertThat(
            actions,
            Equals(["first", "between", "last"]),
        )

    def test_failure(self):
        """
        ``bracket`` calls ``first`` then ``between`` then ``last`` and returns a
        ``Deferred`` that fires with the failure result of ``between``.
        """

        class SomeException(Exception):
            pass

        actions = []
        first = partial(actions.append, "first")

        def between():
            actions.append("between")
            return self.wrap_failure(SomeException())

        last = partial(actions.append, "last")
        self.assertThat(
            bracket(first, last, between),
            failed(
                AfterPreprocessing(
                    lambda failure: failure.value,
                    IsInstance(SomeException),
                ),
            ),
        )
        self.assertThat(
            actions,
            Equals(["first", "between", "last"]),
        )

    def test_success_with_failing_last(self):
        """
        If the ``between`` action succeeds and the ``last`` action fails then
        ``bracket`` fails the same way as the ``last`` action.
        """

        class SomeException(Exception):
            pass

        actions = []
        first = partial(actions.append, "first")

        def between():
            actions.append("between")
            return self.wrap_success(None)

        def last():
            actions.append("last")
            return self.wrap_failure(SomeException())

        self.assertThat(
            bracket(first, last, between),
            failed(
                AfterPreprocessing(
                    lambda failure: failure.value,
                    IsInstance(SomeException),
                ),
            ),
        )
        self.assertThat(
            actions,
            Equals(["first", "between", "last"]),
        )

    def test_failure_with_failing_last(self):
        """
        If both the ``between`` and ``last`` actions fail then ``bracket`` fails
        the same way as the ``last`` action.
        """

        class SomeException(Exception):
            pass

        class AnotherException(Exception):
            pass

        actions = []
        first = partial(actions.append, "first")

        def between():
            actions.append("between")
            return self.wrap_failure(SomeException())

        def last():
            actions.append("last")
            return self.wrap_failure(AnotherException())

        self.assertThat(
            bracket(first, last, between),
            failed(
                AfterPreprocessing(
                    lambda failure: failure.value,
                    IsInstance(AnotherException),
                ),
            ),
        )
        self.assertThat(
            actions,
            Equals(["first", "between", "last"]),
        )

    def test_first_failure(self):
        """
        If the ``first`` action fails then ``bracket`` fails the same way and
        runs neither the ``between`` nor ``last`` actions.
        """

        class SomeException(Exception):
            pass

        actions = []

        def first():
            actions.append("first")
            return self.wrap_failure(SomeException())

        between = partial(actions.append, "between")
        last = partial(actions.append, "last")

        self.assertThat(
            bracket(first, last, between),
            failed(
                AfterPreprocessing(
                    lambda failure: failure.value,
                    IsInstance(SomeException),
                ),
            ),
        )
        self.assertThat(
            actions,
            Equals(["first"]),
        )


class BracketTests(_BracketTestMixin, TestCase):
    def wrap_success(self, result):
        return result

    def wrap_failure(self, exception):
        raise exception


class SynchronousDeferredBracketTests(_BracketTestMixin, TestCase):
    def wrap_success(self, result):
        return succeed(result)

    def wrap_failure(self, exception):
        return fail(exception)
