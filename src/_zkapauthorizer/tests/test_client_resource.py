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
Tests for the web resource provided by the client part of the Tahoe-LAFS
plugin.
"""

from __future__ import (
    absolute_import,
)

import attr

from .._base64 import (
    urlsafe_b64decode,
)

from datetime import (
    datetime,
)
from json import (
    dumps,
    loads,
)
from io import (
    BytesIO,
)
from urllib import (
    quote,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    MatchesStructure,
    MatchesAll,
    MatchesAny,
    MatchesPredicate,
    AllMatch,
    HasLength,
    IsInstance,
    ContainsDict,
    AfterPreprocessing,
    Equals,
    Always,
    GreaterThan,
    Is,
)
from testtools.twistedsupport import (
    CaptureTwistedLogs,
    succeeded,
)
from testtools.content import (
    text_content,
)

from aniso8601 import (
    parse_datetime,
)

from fixtures import (
    TempDir,
)

from hypothesis import (
    given,
    note,
)
from hypothesis.strategies import (
    one_of,
    just,
    fixed_dictionaries,
    lists,
    integers,
    binary,
    text,
    datetimes,
)

from twisted.internet.defer import (
    Deferred,
    maybeDeferred,
    gatherResults,
)
from twisted.internet.task import (
    Cooperator,
)
from twisted.web.http import (
    OK,
    NOT_FOUND,
    BAD_REQUEST,
)
from twisted.web.resource import (
    IResource,
    getChildForRequest,
)
from twisted.web.client import (
    FileBodyProducer,
    readBody,
)

from treq.testing import (
    RequestTraversalAgent,
)

from ..model import (
    Voucher,
    Redeeming,
    Redeemed,
    DoubleSpend,
    Unpaid,
    Error,
    VoucherStore,
    memory_connect,
)
from ..resource import (
    from_configuration,
)

from ..storage_common import (
    BYTES_PER_PASS,
    required_passes,
)

from .strategies import (
    tahoe_configs,
    client_unpaidredeemer_configurations,
    client_doublespendredeemer_configurations,
    client_dummyredeemer_configurations,
    client_nonredeemer_configurations,
    client_errorredeemer_configurations,
    vouchers,
    requests,
)
from .matchers import (
    Provides,
)

TRANSIENT_ERROR = u"something went wrong, who knows what"

# Helper to work-around https://github.com/twisted/treq/issues/161
def uncooperator(started=True):
    return Cooperator(
        # Don't stop consuming the iterator until it's done.
        terminationPredicateFactory=lambda: lambda: False,
        scheduler=lambda what: (what(), object())[1],
        started=started,
    )



def is_not_json(bytestring):
    """
    :param bytes bytestring: A candidate byte string to inspect.

    :return bool: ``False`` if and only if ``bytestring`` is JSON encoded.
    """
    try:
        loads(bytestring)
    except:
        return True
    return False

def not_vouchers():
    """
    Builds unicode strings which are not legal vouchers.
    """
    return one_of(
        text().filter(
            lambda t: (
                not is_urlsafe_base64(t)
            ),
        ),
        vouchers().map(
            # Turn a valid voucher into a voucher that is invalid only by
            # containing a character from the base64 alphabet in place of one
            # from the urlsafe-base64 alphabet.
            lambda voucher: u"/" + voucher[1:],
        ),
    )

def is_urlsafe_base64(text):
    """
    :param unicode text: A candidate unicode string to inspect.

    :return bool: ``True`` if and only if ``text`` is urlsafe-base64 encoded
    """
    try:
        urlsafe_b64decode(text)
    except:
        return False
    return True


def invalid_bodies():
    """
    Build byte strings that ``PUT /voucher`` considers invalid.
    """
    return one_of(
        # The wrong key but the right kind of value.
        fixed_dictionaries({
            u"some-key": vouchers(),
        }).map(dumps),
        # The right key but the wrong kind of value.
        fixed_dictionaries({
            u"voucher": one_of(
                integers(),
                not_vouchers(),
            ),
        }).map(dumps),
        # Not even JSON
        binary().filter(is_not_json),
    )


def root_from_config(config, now):
    """
    Create a client root resource from a Tahoe-LAFS configuration.

    :param _Config config: The Tahoe-LAFS configuration.

    :param now: A no-argument callable that returns the time of the call as a
        ``datetime`` instance.

    :return IResource: The root client resource.
    """
    return from_configuration(
        config,
        VoucherStore.from_node_config(
            config,
            now,
            memory_connect,
        ),
    )


class ResourceTests(TestCase):
    """
    General tests for the resources exposed by the plugin.
    """
    @given(tahoe_configs(), requests(just([u"unblinded-token"]) | just([u"voucher"])))
    def test_reachable(self, get_config, request):
        """
        A resource is reachable at a child of the resource returned by
        ``from_configuration``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)
        self.assertThat(
            getChildForRequest(root, request),
            Provides([IResource]),
        )


class UnblindedTokenTests(TestCase):
    """
    Tests relating to ``/unblinded-token`` as implemented by the
    ``_zkapauthorizer.resource`` module.
    """
    def setUp(self):
        super(UnblindedTokenTests, self).setUp()
        self.useFixture(CaptureTwistedLogs())


    @given(tahoe_configs(), vouchers(), integers(min_value=0, max_value=100))
    def test_get(self, get_config, voucher, num_tokens):
        """
        When the unblinded token collection receives a **GET**, the response is
        the total number of unblinded tokens in the system, the unblinded
        tokens themselves, and information about tokens spent on recent lease
        maintenance activity.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)

        if num_tokens:
            # Put in a number of tokens with which to test.
            redeeming = root.controller.redeem(voucher, num_tokens)
            # Make sure the operation completed before proceeding.
            self.assertThat(
                redeeming,
                succeeded(Always()),
            )

        agent = RequestTraversalAgent(root)
        requesting = agent.request(
            b"GET",
            b"http://127.0.0.1/unblinded-token",
        )
        self.addDetail(
            u"requesting result",
            text_content(u"{}".format(vars(requesting.result))),
        )
        self.assertThat(
            requesting,
            succeeded_with_unblinded_tokens(num_tokens, num_tokens),
        )

    @given(tahoe_configs(), vouchers(), integers(min_value=0, max_value=100), integers(min_value=0))
    def test_get_limit(self, get_config, voucher, num_tokens, limit):
        """
        When the unblinded token collection receives a **GET** with a **limit**
        query argument, it returns no more unblinded tokens than indicated by
        the limit.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)

        if num_tokens:
            # Put in a number of tokens with which to test.
            redeeming = root.controller.redeem(voucher, num_tokens)
            # Make sure the operation completed before proceeding.
            self.assertThat(
                redeeming,
                succeeded(Always()),
            )

        agent = RequestTraversalAgent(root)
        requesting = agent.request(
            b"GET",
            b"http://127.0.0.1/unblinded-token?limit={}".format(limit),
        )
        self.addDetail(
            u"requesting result",
            text_content(u"{}".format(vars(requesting.result))),
        )
        self.assertThat(
            requesting,
            succeeded_with_unblinded_tokens(num_tokens, min(num_tokens, limit)),
        )

    @given(tahoe_configs(), vouchers(), integers(min_value=0, max_value=100), text(max_size=64))
    def test_get_position(self, get_config, voucher, num_tokens, position):
        """
        When the unblinded token collection receives a **GET** with a **position**
        query argument, it returns all unblinded tokens which sort greater
        than the position and no others.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)

        if num_tokens:
            # Put in a number of tokens with which to test.
            redeeming = root.controller.redeem(voucher, num_tokens)
            # Make sure the operation completed before proceeding.
            self.assertThat(
                redeeming,
                succeeded(Always()),
            )

        agent = RequestTraversalAgent(root)
        requesting = agent.request(
            b"GET",
            b"http://127.0.0.1/unblinded-token?position={}".format(
                quote(position.encode("utf-8"), safe=b""),
            ),
        )
        self.addDetail(
            u"requesting result",
            text_content(u"{}".format(vars(requesting.result))),
        )
        self.assertThat(
            requesting,
            succeeded_with_unblinded_tokens_with_matcher(
                num_tokens,
                AllMatch(
                    MatchesAll(
                        GreaterThan(position),
                        IsInstance(unicode),
                    ),
                ),
                matches_lease_maintenance_spending(),
            ),
        )

    @given(tahoe_configs(), vouchers(), integers(min_value=1, max_value=100))
    def test_get_order_matches_use_order(self, get_config, voucher, num_tokens):
        """
        The first unblinded token returned in a response to a **GET** request is
        the first token to be used to authorize a storage request.
        """
        def after(d, f):
            new_d = Deferred()
            def f_and_continue(result):
                maybeDeferred(f).chainDeferred(new_d)
                return result
            d.addCallback(f_and_continue)
            return new_d

        def get_tokens():
            d = agent.request(
                b"GET",
                b"http://127.0.0.1/unblinded-token",
            )
            d.addCallback(readBody)
            d.addCallback(
                lambda body: loads(body)[u"unblinded-tokens"],
            )
            return d

        def use_a_token():
            root.store.extract_unblinded_tokens(1)

        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)

        # Put in a number of tokens with which to test.
        redeeming = root.controller.redeem(voucher, num_tokens)
        # Make sure the operation completed before proceeding.
        self.assertThat(
            redeeming,
            succeeded(Always()),
        )

        agent = RequestTraversalAgent(root)
        getting_initial_tokens = get_tokens()
        using_a_token = after(getting_initial_tokens, use_a_token)
        getting_tokens_after = after(using_a_token, get_tokens)

        self.assertThat(
            gatherResults([getting_initial_tokens, getting_tokens_after]),
            succeeded(
                MatchesPredicate(
                    lambda (initial_tokens, tokens_after): initial_tokens[1:] == tokens_after,
                    u"initial, after (%s): initial[1:] != after",
                ),
            ),
        )

    @given(
        tahoe_configs(),
        lists(
            lists(
                integers(min_value=0, max_value=2 ** 63 - 1),
                min_size=1,
            ),
        ),
        datetimes(),
    )
    def test_latest_lease_maintenance_spending(self, get_config, size_observations, now):
        """
        The most recently completed record of lease maintenance spending activity
        is reported in the response to a **GET** request.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, lambda: now)

        # Put some activity into it.
        total = 0
        activity = root.store.start_lease_maintenance()
        for sizes in size_observations:
            total += required_passes(BYTES_PER_PASS, sizes)
            activity.observe(sizes)
        activity.finish()

        agent = RequestTraversalAgent(root)
        d = agent.request(
            b"GET",
            b"http://127.0.0.1/unblinded-token",
        )
        d.addCallback(readBody)
        d.addCallback(
            lambda body: loads(body)[u"lease-maintenance-spending"],
        )
        self.assertThat(
            d,
            succeeded(Equals({
                "when": now.isoformat(),
                "count": total,
            })),
        )


def succeeded_with_unblinded_tokens_with_matcher(
        all_token_count,
        match_unblinded_tokens,
        match_lease_maint_spending,
):
    """
    :return: A matcher which matches a Deferred which fires with a response
        like the one returned by the **unblinded-tokens** endpoint.

    :param int all_token_count: The expected value in the ``total`` field of
        the response.

    :param match_unblinded_tokens: A matcher for the ``unblinded-tokens``
        field of the response.

    :param match_lease_maint_spending: A matcher for the
        ``lease-maintenance-spending`` field of the response.
    """
    return succeeded(
        MatchesAll(
            ok_response(headers=application_json()),
            AfterPreprocessing(
                json_content,
                succeeded(
                    ContainsDict({
                        u"total": Equals(all_token_count),
                        u"unblinded-tokens": match_unblinded_tokens,
                        u"lease-maintenance-spending": match_lease_maint_spending,
                    }),
                ),
            ),
        ),
    )

def succeeded_with_unblinded_tokens(all_token_count, returned_token_count):
    """
    :return: A matcher which matches a Deferred which fires with a response
        like the one returned by the **unblinded-tokens** endpoint.

    :param int all_token_count: The expected value in the ``total`` field of
        the response.

    :param int returned_token_count: The expected number of tokens in the
       ``unblinded-tokens`` field of the response.
    """
    return succeeded_with_unblinded_tokens_with_matcher(
        all_token_count,
        MatchesAll(
            HasLength(returned_token_count),
            AllMatch(IsInstance(unicode)),
        ),
        matches_lease_maintenance_spending(),
    )

def matches_lease_maintenance_spending():
    """
    :return: A matcher which matches the value of the
        *lease-maintenance-spending* key in the ``unblinded-tokens`` endpoint
        response.
    """
    return MatchesAny(
        Is(None),
        ContainsDict({
            u"when": matches_iso8601_datetime(),
            u"amount": matches_positive_integer(),
        }),
    )

def matches_positive_integer():
    return MatchesAll(
        IsInstance(int),
        GreaterThan(0),
    )

def matches_iso8601_datetime():
    """
    :return: A matcher which matches unicode strings which can be parsed as an
        ISO8601 datetime string.
    """
    return MatchesAll(
        IsInstance(unicode),
        AfterPreprocessing(
            parse_datetime,
            lambda d: Always(),
        ),
    )

class VoucherTests(TestCase):
    """
    Tests relating to ``/voucher`` as implemented by the
    ``_zkapauthorizer.resource`` module and its handling of
    vouchers.
    """
    def setUp(self):
        super(VoucherTests, self).setUp()
        self.useFixture(CaptureTwistedLogs())


    @given(tahoe_configs(), vouchers())
    def test_put_voucher(self, get_config, voucher):
        """
        When a voucher is ``PUT`` to ``VoucherCollection`` it is passed in to the
        redemption model object for handling and an ``OK`` response is
        returned.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        producer = FileBodyProducer(
            BytesIO(dumps({u"voucher": voucher})),
            cooperator=uncooperator(),
        )
        requesting = agent.request(
            b"PUT",
            b"http://127.0.0.1/voucher",
            bodyProducer=producer,
        )
        self.addDetail(
            u"requesting result",
            text_content(u"{}".format(vars(requesting.result))),
        )
        self.assertThat(
            requesting,
            succeeded(
                ok_response(),
            ),
        )

    @given(tahoe_configs(), invalid_bodies())
    def test_put_invalid_body(self, get_config, body):
        """
        If the body of a ``PUT`` to ``VoucherCollection`` does not consist of an
        object with a single *voucher* property then the response is *BAD
        REQUEST*.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        producer = FileBodyProducer(
            BytesIO(body),
            cooperator=uncooperator(),
        )
        requesting = agent.request(
            b"PUT",
            b"http://127.0.0.1/voucher",
            bodyProducer=producer,
        )
        self.addDetail(
            u"requesting result",
            text_content(u"{}".format(vars(requesting.result))),
        )
        self.assertThat(
            requesting,
            succeeded(
                bad_request_response(),
            ),
        )

    @given(tahoe_configs(), not_vouchers())
    def test_get_invalid_voucher(self, get_config, not_voucher):
        """
        When a syntactically invalid voucher is requested with a ``GET`` to a
        child of ``VoucherCollection`` the response is **BAD REQUEST**.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        url = u"http://127.0.0.1/voucher/{}".format(
            quote(
                not_voucher.encode("utf-8"),
                safe=b"",
            ).decode("utf-8"),
        ).encode("ascii")
        requesting = agent.request(
            b"GET",
            url,
        )
        self.assertThat(
            requesting,
            succeeded(
                bad_request_response(),
            ),
        )


    @given(tahoe_configs(), vouchers())
    def test_get_unknown_voucher(self, get_config, voucher):
        """
        When a voucher is requested with a ``GET`` to a child of
        ``VoucherCollection`` the response is **NOT FOUND** if the voucher
        hasn't previously been submitted with a ``PUT``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        requesting = agent.request(
            b"GET",
            u"http://127.0.0.1/voucher/{}".format(voucher).encode("ascii"),
        )
        self.assertThat(
            requesting,
            succeeded(
                not_found_response(),
            ),
        )

    @given(tahoe_configs(client_nonredeemer_configurations()), datetimes(), vouchers())
    def test_get_known_voucher_redeeming(self, get_config, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which is actively being redeemed, about
        the voucher are included in a json-encoded response body.
        """
        return self._test_get_known_voucher(
            get_config,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                created=Equals(now),
                state=Equals(Redeeming(
                    started=now,
                )),
            ),
        )

    @given(tahoe_configs(client_dummyredeemer_configurations()), datetimes(), vouchers())
    def test_get_known_voucher_redeemed(self, get_config, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which has been redeemed, about the voucher
        are included in a json-encoded response body.
        """
        return self._test_get_known_voucher(
            get_config,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                created=Equals(now),
                state=Equals(Redeemed(
                    finished=now,
                    # Value duplicated from PaymentController.redeem default.
                    # Should do this better.
                    token_count=100,
                )),
            ),
        )

    @given(tahoe_configs(client_doublespendredeemer_configurations()), datetimes(), vouchers())
    def test_get_known_voucher_doublespend(self, get_config, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which has failed redemption because it was
        already redeemed, about the voucher are included in a json-encoded
        response body.
        """
        return self._test_get_known_voucher(
            get_config,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                created=Equals(now),
                state=Equals(DoubleSpend(
                    finished=now,
                )),
            ),
        )

    @given(tahoe_configs(client_unpaidredeemer_configurations()), datetimes(), vouchers())
    def test_get_known_voucher_unpaid(self, get_config, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which has failed redemption because it has
        not been paid for yet, about the voucher are included in a
        json-encoded response body.
        """
        return self._test_get_known_voucher(
            get_config,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                created=Equals(now),
                state=Equals(Unpaid(
                    finished=now,
                )),
            ),
        )

    @given(tahoe_configs(client_errorredeemer_configurations(TRANSIENT_ERROR)), datetimes(), vouchers())
    def test_get_known_voucher_error(self, get_config, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which has failed redemption due to any
        kind of transient conditions, about the voucher are included in a
        json-encoded response body.
        """
        return self._test_get_known_voucher(
            get_config,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                created=Equals(now),
                state=Equals(Error(
                    finished=now,
                    details=TRANSIENT_ERROR,
                )),
            ),
        )

    def _test_get_known_voucher(self, get_config, now, voucher, voucher_matcher):
        """
        Assert that a voucher that is ``PUT`` and then ``GET`` is represented in
        the JSON response.

        :param voucher_matcher: A matcher which matches the voucher expected
            to be returned by the ``GET``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, lambda: now)
        agent = RequestTraversalAgent(root)

        producer = FileBodyProducer(
            BytesIO(dumps({u"voucher": voucher})),
            cooperator=uncooperator(),
        )
        putting = agent.request(
            b"PUT",
            b"http://127.0.0.1/voucher",
            bodyProducer=producer,
        )
        self.assertThat(
            putting,
            succeeded(
                ok_response(),
            ),
        )

        getting = agent.request(
            b"GET",
            u"http://127.0.0.1/voucher/{}".format(
                quote(
                    voucher.encode("utf-8"),
                    safe=b"",
                ).decode("utf-8"),
            ).encode("ascii"),
        )
        self.assertThat(
            getting,
            succeeded(
                MatchesAll(
                    ok_response(headers=application_json()),
                    AfterPreprocessing(
                        readBody,
                        succeeded(
                            AfterPreprocessing(
                                Voucher.from_json,
                                voucher_matcher,
                            ),
                        ),
                    ),
                ),
            ),
        )

    @given(tahoe_configs(), datetimes(), lists(vouchers(), unique=True))
    def test_list_vouchers(self, get_config, now, vouchers):
        """
        A ``GET`` to the ``VoucherCollection`` itself returns a list of existing
        vouchers.
        """
        return self._test_list_vouchers(
            get_config,
            now,
            vouchers,
            Equals({
                u"vouchers": list(
                    Voucher(
                        voucher,
                        created=now,
                        state=Redeemed(
                            finished=now,
                            # Value duplicated from
                            # PaymentController.redeem
                            # default.  Should do this better.
                            token_count=100,
                        ),
                    ).marshal()
                    for voucher
                    in vouchers
                ),
            }),
        )

    @given(
        tahoe_configs(client_unpaidredeemer_configurations()),
        datetimes(),
        lists(vouchers(), unique=True),
    )
    def test_list_vouchers_transient_states(self, get_config, now, vouchers):
        """
        A ``GET`` to the ``VoucherCollection`` itself returns a list of existing
        vouchers including state information that reflects transient states.
        """
        return self._test_list_vouchers(
            get_config,
            now,
            vouchers,
            Equals({
                u"vouchers": list(
                    Voucher(
                        voucher,
                        created=now,
                        state=Unpaid(
                            finished=now,
                        ),
                    ).marshal()
                    for voucher
                    in vouchers
                ),
            }),
        )

    def _test_list_vouchers(self, get_config, now, vouchers, match_response_object):
        # Hypothesis causes our test case instances to be re-used many times
        # between setUp and tearDown.  Avoid re-using the same temporary
        # directory for every Hypothesis iteration because this test leaves
        # state behind that invalidates future iterations.
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config, lambda: now)
        agent = RequestTraversalAgent(root)

        note("{} vouchers".format(len(vouchers)))

        for voucher in vouchers:
            producer = FileBodyProducer(
                BytesIO(dumps({u"voucher": voucher})),
                cooperator=uncooperator(),
            )
            putting = agent.request(
                b"PUT",
                b"http://127.0.0.1/voucher",
                bodyProducer=producer,
            )
            self.assertThat(
                putting,
                succeeded(
                    ok_response(),
                ),
            )

        getting = agent.request(
            b"GET",
            b"http://127.0.0.1/voucher",
        )

        self.assertThat(
            getting,
            succeeded(
                MatchesAll(
                    ok_response(headers=application_json()),
                    AfterPreprocessing(
                        json_content,
                        succeeded(
                            match_response_object,
                        ),
                    ),
                ),
            ),
        )


def application_json():
    return AfterPreprocessing(
        lambda h: h.getRawHeaders(u"content-type"),
        Equals([u"application/json"]),
    )


def json_content(response):
    reading = readBody(response)
    reading.addCallback(loads)
    return reading


def ok_response(headers=None):
    return match_response(OK, headers)


def not_found_response(headers=None):
    return match_response(NOT_FOUND, headers)


def bad_request_response(headers=None):
    return match_response(BAD_REQUEST, headers)


def match_response(code, headers):
    if headers is None:
        headers = Always()
    return _MatchResponse(
        code=Equals(code),
        headers=headers,
    )


@attr.s
class _MatchResponse(object):
    code = attr.ib()
    headers = attr.ib()
    _details = attr.ib(default=attr.Factory(dict))

    def match(self, response):
        self._details.update({
            u"code": response.code,
            u"headers": response.headers.getAllRawHeaders(),
        })
        return MatchesStructure(
            code=self.code,
            headers=self.headers,
        ).match(response)

    def get_details(self):
        return self._details
