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

from datetime import datetime
from io import BytesIO
from typing import Optional, Set
from urllib.parse import quote

import attr
from allmydata.client import config_from_string
from aniso8601 import parse_datetime
from fixtures import TempDir
from hypothesis import given, note
from hypothesis.strategies import (
    SearchStrategy,
    binary,
    builds,
    datetimes,
    dictionaries,
    fixed_dictionaries,
    integers,
    just,
    lists,
    none,
    one_of,
    sampled_from,
    text,
    tuples,
)
from testtools import TestCase
from testtools.content import text_content
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    ContainsDict,
    Equals,
    GreaterThan,
    Is,
    IsInstance,
    MatchesAll,
    MatchesAny,
    MatchesStructure,
)
from testtools.twistedsupport import CaptureTwistedLogs, succeeded
from treq.testing import RequestTraversalAgent
from twisted.internet.task import Clock, Cooperator
from twisted.python.filepath import FilePath
from twisted.web.client import FileBodyProducer, readBody
from twisted.web.http import BAD_REQUEST, NOT_FOUND, NOT_IMPLEMENTED, OK, UNAUTHORIZED
from twisted.web.http_headers import Headers
from twisted.web.resource import IResource, getChildForRequest

from .. import __version__ as zkapauthorizer_version
from .._base64 import urlsafe_b64decode
from .._json import dumps_utf8
from ..api import NAME
from ..configutil import config_string_from_sections
from ..model import (
    DoubleSpend,
    Error,
    Redeemed,
    Redeeming,
    Unpaid,
    Voucher,
    VoucherStore,
    memory_connect,
)
from ..pricecalculator import PriceCalculator
from ..resource import NUM_TOKENS, from_configuration, get_token_count
from ..storage_common import (
    get_configured_allowed_public_keys,
    get_configured_pass_value,
    required_passes,
)
from .json import loads
from .matchers import Provides, between, matches_response
from .strategies import (
    api_auth_tokens,
    client_doublespendredeemer_configurations,
    client_dummyredeemer_configurations,
    client_errorredeemer_configurations,
    client_nonredeemer_configurations,
    client_unpaidredeemer_configurations,
    direct_tahoe_configs,
    posix_timestamps,
    request_paths,
    requests,
    share_parameters,
    tahoe_configs,
    vouchers,
)

TRANSIENT_ERROR = "something went wrong, who knows what"

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
    Builds byte strings which are not legal vouchers.
    """
    return one_of(
        text()
        .filter(
            lambda t: (not is_urlsafe_base64(t)),
        )
        .map(lambda t: t.encode("utf-8")),
        vouchers().map(
            # Turn a valid voucher into a voucher that is invalid only by
            # containing a character from the base64 alphabet in place of one
            # from the urlsafe-base64 alphabet.
            lambda voucher: b"/"
            + voucher[1:],
        ),
    )


def is_urlsafe_base64(text):
    """
    :param str text: A candidate text string to inspect.

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
        fixed_dictionaries(
            {
                "some-key": vouchers().map(lambda v: v.decode("utf-8")),
            }
        ).map(dumps_utf8),
        # The right key but the wrong kind of value.
        fixed_dictionaries(
            {
                "voucher": one_of(
                    integers(),
                    not_vouchers().map(lambda v: v.decode("utf-8")),
                ),
            }
        ).map(dumps_utf8),
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
        clock=Clock(),
    )


def authorized_request(api_auth_token, agent, method, uri, headers=None, data=None):
    """
    Issue a request with the required token-based authorization header value.

    :param bytes api_auth_token: The API authorization token to include.

    :param IAgent agent: The agent to use to issue the request.

    :param bytes method: The HTTP method for the request.

    :param bytes uri: The URI for the request.

    :param ({bytes: [bytes]})|None headers: If not ``None``, extra request
        headers to include.  The **Authorization** header will be overwritten
        if it is present.

    :param BytesIO|None data: If not ``None``, the request body.

    :return: A ``Deferred`` like the one returned by ``IAgent.request``.
    """
    if data is None:
        bodyProducer = None
    else:
        bodyProducer = FileBodyProducer(data, cooperator=uncooperator())
    if headers is None:
        headers = Headers()
    else:
        headers = Headers(headers)
    headers.setRawHeaders(
        "authorization",
        [b"tahoe-lafs " + api_auth_token],
    )
    return agent.request(
        method,
        uri,
        headers=headers,
        bodyProducer=bodyProducer,
    )


def get_config_with_api_token(tempdir, get_config, api_auth_token):
    """
    Get a ``_Config`` object.

    :param TempDir tempdir: A temporary directory in which to create the
        Tahoe-LAFS node associated with the configuration.

    :param (bytes -> bytes -> _Config) get_config: A function which takes a
        node directory and a Foolscap "portnum" filename and returns the
        configuration object.

    :param bytes api_auth_token: The HTTP API authorization token to write to
        the node directory.
    """
    basedir = tempdir.join("tahoe")
    config = get_config(basedir, "tub.port")
    add_api_token_to_config(
        basedir,
        config,
        api_auth_token,
    )
    return config


def add_api_token_to_config(basedir, config, api_auth_token):
    """
    Create a private directory beneath the given base directory, point the
    given config at it, and write the given API auth token to it.
    """
    FilePath(basedir).child("private").makedirs()
    config._basedir = basedir
    config.write_private_config("api_auth_token", api_auth_token)


class FromConfigurationTests(TestCase):
    """
    Tests for ``from_configuration``.
    """

    @given(tahoe_configs())
    def test_allowed_public_keys(self, get_config):
        """
        The controller created by ``from_configuration`` is configured to allow
        the public keys found in the configuration.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join("tahoe"), "tub.port")
        allowed_public_keys = get_configured_allowed_public_keys(config)

        # root_from_config is just an easier way to call from_configuration
        root = root_from_config(config, datetime.now)
        self.assertThat(
            root.controller,
            MatchesStructure(
                allowed_public_keys=Equals(allowed_public_keys),
            ),
        )


class GetTokenCountTests(TestCase):
    """
    Tests for ``get_token_count``.
    """

    @given(one_of(none(), integers(min_value=16)))
    def test_get_token_count(self, token_count):
        """
        ``get_token_count`` returns the integer value of the
        ``default-token-count`` item from the given configuration object.
        """
        plugin_name = "hello-world"
        if token_count is None:
            expected_count = NUM_TOKENS
            token_config = {}
        else:
            expected_count = token_count
            token_config = {"default-token-count": f"{expected_count}"}

        config_text = config_string_from_sections(
            [
                {
                    "storageclient.plugins." + plugin_name: token_config,
                }
            ]
        )
        node_config = config_from_string(
            self.useFixture(TempDir()).join("tahoe"),
            "tub.port",
            config_text.encode("utf-8"),
        )
        self.assertThat(
            get_token_count(plugin_name, node_config),
            Equals(expected_count),
        )


class ResourceTests(TestCase):
    """
    General tests for the resources exposed by the plugin.
    """

    @given(
        tahoe_configs(),
        request_paths(),
    )
    def test_unauthorized(self, get_config, path):
        """
        A request for any resource without the required authorization token
        receives a 401 response.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join("tahoe"), "tub.port")
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        requesting = agent.request(
            b"GET",
            b"http://127.0.0.1/" + b"/".join(path),
        )
        responses = []
        requesting.addCallback(responses.append)
        self.assertThat(
            requesting,
            succeeded(Always()),
        )
        [response] = responses

        self.assertThat(
            response.code,
            Equals(UNAUTHORIZED),
        )

    @given(
        tahoe_configs(),
        requests(
            sampled_from(
                [
                    [b"unblinded-token"],
                    [b"voucher"],
                    [b"version"],
                ]
            )
        ),
    )
    def test_reachable(self, get_config, request):
        """
        A resource is reachable at a child of the resource returned by
        ``from_configuration``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join("tahoe"), "tub.port")
        root = root_from_config(config, datetime.now)
        self.assertThat(
            getChildForRequest(root, request),
            Provides([IResource]),
        )

    @given(
        tahoe_configs(),
        api_auth_tokens(),
    )
    def test_version(self, get_config, api_auth_token):
        """
        The ZKAPAuthorizer package version is available in a JSON response to a
        **GET** to ``/version``.
        """
        config = get_config_with_api_token(
            self.useFixture(TempDir()),
            get_config,
            api_auth_token,
        )
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        requesting = authorized_request(
            api_auth_token,
            agent,
            b"GET",
            b"http://127.0.0.1/version",
        )
        self.assertThat(
            requesting,
            succeeded(
                matches_response(
                    code_matcher=Equals(OK),
                    body_matcher=AfterPreprocessing(
                        loads,
                        Equals({"version": zkapauthorizer_version}),
                    ),
                ),
            ),
        )


def maybe_extra_tokens():
    """
    Build either ``None`` or a small integer for use in determining a number
    of additional tokens to create in some tests.
    """
    # We might want to have some unblinded tokens or we might not.
    return one_of(
        just(None),
        # If we do, we can't have fewer than the number of redemption groups
        # which we don't know until we're further inside the test.  So supply
        # an amount to add to that, in the case where we have tokens at all.
        integers(min_value=0, max_value=100),
    )


class UnblindedTokenTests(TestCase):
    """
    Tests relating to ``/unblinded-token`` as implemented by the
    ``_zkapauthorizer.resource`` module.
    """

    def setUp(self):
        super(UnblindedTokenTests, self).setUp()
        self.useFixture(CaptureTwistedLogs())

    @given(
        tahoe_configs(),
        api_auth_tokens(),
        lists(
            lists(
                integers(min_value=0, max_value=2 ** 63 - 1),
                min_size=1,
            ),
        ),
        datetimes(),
    )
    def test_latest_lease_maintenance_spending(
        self, get_config, api_auth_token, size_observations, now
    ):
        """
        The most recently completed record of lease maintenance spending activity
        is reported in the response to a **GET** request.
        """
        config = get_config_with_api_token(
            self.useFixture(TempDir()),
            get_config,
            api_auth_token,
        )
        root = root_from_config(config, lambda: now)

        # Put some activity into it.
        total = 0
        activity = root.store.start_lease_maintenance()
        for sizes in size_observations:
            total += required_passes(root.store.pass_value, sizes)
            activity.observe(sizes)
        activity.finish()

        agent = RequestTraversalAgent(root)
        d = authorized_request(
            api_auth_token,
            agent,
            b"GET",
            b"http://127.0.0.1/lease-maintenance",
        )
        d.addCallback(readBody)
        d.addCallback(
            lambda body: loads(body)["spending"],
        )
        self.assertThat(
            d,
            succeeded(
                Equals(
                    {
                        "when": now.isoformat(),
                        "count": total,
                    }
                )
            ),
        )


def matches_lease_maintenance_spending():
    """
    :return: A matcher which matches the value of the *spending* key in the
      ``lease-maintenance`` endpoint response.
    """
    return MatchesAny(
        Is(None),
        ContainsDict(
            {
                "when": matches_iso8601_datetime(),
                "amount": matches_positive_integer(),
            }
        ),
    )


def matches_positive_integer():
    return MatchesAll(
        IsInstance(int),
        GreaterThan(0),
    )


def matches_iso8601_datetime():
    """
    :return: A matcher which matches text strings which can be parsed as an
        ISO8601 datetime string.
    """
    return MatchesAll(
        IsInstance(str),
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

    @given(tahoe_configs(), api_auth_tokens(), vouchers())
    def test_put_voucher(self, get_config, api_auth_token, voucher):
        """
        When a voucher is ``PUT`` to ``VoucherCollection`` it is passed in to the
        redemption model object for handling and an ``OK`` response is
        returned.
        """
        config = get_config_with_api_token(
            self.useFixture(TempDir()),
            get_config,
            api_auth_token,
        )
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        data = BytesIO(dumps_utf8({"voucher": voucher.decode("ascii")}))
        requesting = authorized_request(
            api_auth_token,
            agent,
            b"PUT",
            b"http://127.0.0.1/voucher",
            data=data,
        )
        self.addDetail(
            "requesting result",
            text_content(f"{vars(requesting.result)}"),
        )
        self.assertThat(
            requesting,
            succeeded(
                ok_response(),
            ),
        )

    @given(tahoe_configs(), api_auth_tokens(), invalid_bodies())
    def test_put_invalid_body(self, get_config, api_auth_token, body):
        """
        If the body of a ``PUT`` to ``VoucherCollection`` does not consist of an
        object with a single *voucher* property then the response is *BAD
        REQUEST*.
        """
        config = get_config_with_api_token(
            self.useFixture(TempDir()),
            get_config,
            api_auth_token,
        )
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        requesting = authorized_request(
            api_auth_token,
            agent,
            b"PUT",
            b"http://127.0.0.1/voucher",
            data=BytesIO(body),
        )
        self.addDetail(
            "requesting result",
            text_content(f"{vars(requesting.result)}"),
        )
        self.assertThat(
            requesting,
            succeeded(
                bad_request_response(),
            ),
        )

    @given(tahoe_configs(), api_auth_tokens(), not_vouchers())
    def test_get_invalid_voucher(self, get_config, api_auth_token, not_voucher):
        """
        When a syntactically invalid voucher is requested with a ``GET`` to a
        child of ``VoucherCollection`` the response is **BAD REQUEST**.
        """
        config = get_config_with_api_token(
            self.useFixture(TempDir()),
            get_config,
            api_auth_token,
        )
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        url = "http://127.0.0.1/voucher/{}".format(
            quote(
                not_voucher,
                safe=b"",
            ),
        ).encode("ascii")
        requesting = authorized_request(
            api_auth_token,
            agent,
            b"GET",
            url,
        )
        self.assertThat(
            requesting,
            succeeded(
                bad_request_response(),
            ),
        )

    @given(tahoe_configs(), api_auth_tokens(), vouchers())
    def test_get_unknown_voucher(self, get_config, api_auth_token, voucher):
        """
        When a voucher is requested with a ``GET`` to a child of
        ``VoucherCollection`` the response is **NOT FOUND** if the voucher
        hasn't previously been submitted with a ``PUT``.
        """
        config = get_config_with_api_token(
            self.useFixture(TempDir()),
            get_config,
            api_auth_token,
        )
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        requesting = authorized_request(
            api_auth_token,
            agent,
            b"GET",
            b"http://127.0.0.1/voucher/" + voucher,
        )
        self.assertThat(
            requesting,
            succeeded(
                not_found_response(),
            ),
        )

    @given(
        direct_tahoe_configs(client_nonredeemer_configurations()),
        api_auth_tokens(),
        datetimes(),
        vouchers(),
    )
    def test_get_known_voucher_redeeming(self, config, api_auth_token, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which is actively being redeemed, about
        the voucher are included in a json-encoded response body.
        """
        count = get_token_count(NAME, config)
        return self._test_get_known_voucher(
            config,
            api_auth_token,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                expected_tokens=Equals(count),
                created=Equals(now),
                state=Equals(
                    Redeeming(
                        started=now,
                        counter=0,
                    )
                ),
            ),
        )

    @given(
        direct_tahoe_configs(client_dummyredeemer_configurations()),
        api_auth_tokens(),
        datetimes(),
        vouchers(),
    )
    def test_get_known_voucher_redeemed(self, config, api_auth_token, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which has been redeemed, about the voucher
        are included in a json-encoded response body.
        """
        count = get_token_count(NAME, config)
        return self._test_get_known_voucher(
            config,
            api_auth_token,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                expected_tokens=Equals(count),
                created=Equals(now),
                state=Equals(
                    Redeemed(
                        finished=now,
                        token_count=count,
                    )
                ),
            ),
        )

    @given(
        direct_tahoe_configs(client_doublespendredeemer_configurations()),
        api_auth_tokens(),
        datetimes(),
        vouchers(),
    )
    def test_get_known_voucher_doublespend(self, config, api_auth_token, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which has failed redemption because it was
        already redeemed, about the voucher are included in a json-encoded
        response body.
        """
        count = get_token_count(NAME, config)
        return self._test_get_known_voucher(
            config,
            api_auth_token,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                expected_tokens=Equals(count),
                created=Equals(now),
                state=Equals(
                    DoubleSpend(
                        finished=now,
                    )
                ),
            ),
        )

    @given(
        direct_tahoe_configs(client_unpaidredeemer_configurations()),
        api_auth_tokens(),
        datetimes(),
        vouchers(),
    )
    def test_get_known_voucher_unpaid(self, config, api_auth_token, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which has failed redemption because it has
        not been paid for yet, about the voucher are included in a
        json-encoded response body.
        """
        count = get_token_count(NAME, config)
        return self._test_get_known_voucher(
            config,
            api_auth_token,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                expected_tokens=Equals(count),
                created=Equals(now),
                state=Equals(
                    Unpaid(
                        finished=now,
                    )
                ),
            ),
        )

    @given(
        direct_tahoe_configs(client_errorredeemer_configurations(TRANSIENT_ERROR)),
        api_auth_tokens(),
        datetimes(),
        vouchers(),
    )
    def test_get_known_voucher_error(self, config, api_auth_token, now, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details, including
        those relevant to a voucher which has failed redemption due to any
        kind of transient conditions, about the voucher are included in a
        json-encoded response body.
        """
        count = get_token_count(NAME, config)
        return self._test_get_known_voucher(
            config,
            api_auth_token,
            now,
            voucher,
            MatchesStructure(
                number=Equals(voucher),
                expected_tokens=Equals(count),
                created=Equals(now),
                state=Equals(
                    Error(
                        finished=now,
                        details=TRANSIENT_ERROR,
                    )
                ),
            ),
        )

    def _test_get_known_voucher(
        self, config, api_auth_token, now, voucher, voucher_matcher
    ):
        """
        Assert that a voucher that is ``PUT`` and then ``GET`` is represented in
        the JSON response.

        :param voucher_matcher: A matcher which matches the voucher expected
            to be returned by the ``GET``.
        """
        add_api_token_to_config(
            self.useFixture(TempDir()).join("tahoe"),
            config,
            api_auth_token,
        )
        root = root_from_config(config, lambda: now)
        agent = RequestTraversalAgent(root)
        putting = authorized_request(
            api_auth_token,
            agent,
            b"PUT",
            b"http://127.0.0.1/voucher",
            data=BytesIO(dumps_utf8({"voucher": voucher.decode("ascii")})),
        )
        self.assertThat(
            putting,
            succeeded(
                ok_response(),
            ),
        )

        getting = authorized_request(
            api_auth_token,
            agent,
            b"GET",
            "http://127.0.0.1/voucher/{}".format(
                quote(
                    voucher,
                    safe="",
                ),
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

    @given(
        direct_tahoe_configs(),
        api_auth_tokens(),
        datetimes(),
        lists(vouchers(), unique=True),
    )
    def test_list_vouchers(self, config, api_auth_token, now, vouchers):
        """
        A ``GET`` to the ``VoucherCollection`` itself returns a list of existing
        vouchers.
        """
        count = get_token_count(NAME, config)
        return self._test_list_vouchers(
            config,
            api_auth_token,
            now,
            vouchers,
            Equals(
                {
                    "vouchers": list(
                        Voucher(
                            number=voucher,
                            expected_tokens=count,
                            created=now,
                            state=Redeemed(
                                finished=now,
                                token_count=count,
                            ),
                        ).marshal()
                        for voucher in vouchers
                    ),
                }
            ),
        )

    @given(
        direct_tahoe_configs(client_unpaidredeemer_configurations()),
        api_auth_tokens(),
        datetimes(),
        lists(vouchers(), unique=True),
    )
    def test_list_vouchers_transient_states(
        self, config, api_auth_token, now, vouchers
    ):
        """
        A ``GET`` to the ``VoucherCollection`` itself returns a list of existing
        vouchers including state information that reflects transient states.
        """
        count = get_token_count(NAME, config)
        return self._test_list_vouchers(
            config,
            api_auth_token,
            now,
            vouchers,
            Equals(
                {
                    "vouchers": list(
                        Voucher(
                            number=voucher,
                            expected_tokens=count,
                            created=now,
                            state=Unpaid(
                                finished=now,
                            ),
                        ).marshal()
                        for voucher in vouchers
                    ),
                }
            ),
        )

    def _test_list_vouchers(
        self, config, api_auth_token, now, vouchers, match_response_object
    ):
        add_api_token_to_config(
            # Hypothesis causes our test case instances to be re-used many
            # times between setUp and tearDown.  Avoid re-using the same
            # temporary directory for every Hypothesis iteration because this
            # test leaves state behind that invalidates future iterations.
            self.useFixture(TempDir()).join("tahoe"),
            config,
            api_auth_token,
        )
        root = root_from_config(config, lambda: now)
        agent = RequestTraversalAgent(root)

        note("{} vouchers".format(len(vouchers)))

        for voucher in vouchers:
            data = BytesIO(dumps_utf8({"voucher": voucher.decode("ascii")}))
            putting = authorized_request(
                api_auth_token,
                agent,
                b"PUT",
                b"http://127.0.0.1/voucher",
                data=data,
            )
            self.assertThat(
                putting,
                succeeded(
                    ok_response(),
                ),
            )

        getting = authorized_request(
            api_auth_token,
            agent,
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


def mime_types(blacklist: Optional[Set[str]] = None) -> SearchStrategy[str]:
    """
    Build MIME types as b"major/minor" byte strings.

    :param blacklist: If not ``None``, MIME types to exclude from the result.
    """
    if blacklist is None:
        blacklist = set()
    return (
        tuples(
            text(),
            text(),
        )
        .map(
            "/".join,
        )
        .filter(
            lambda content_type: content_type not in blacklist,
        )
    )


@attr.s
class Request(object):
    """
    Represent some of the parameters of an HTTP request.
    """

    method = attr.ib()
    headers = attr.ib()
    data = attr.ib()


def bad_calculate_price_requests():
    """
    Build Request instances describing requests which are not allowed at the
    ``/calculate-price`` endpoint.
    """
    good_methods = just(b"POST")
    bad_methods = sampled_from(
        [
            b"GET",
            b"HEAD",
            b"PUT",
            b"PATCH",
            b"OPTIONS",
            b"FOO",
        ]
    )

    good_headers = just({b"content-type": [b"application/json"]})
    bad_headers = fixed_dictionaries(
        {
            b"content-type": mime_types(blacklist={b"application/json"},).map(
                lambda content_type: [content_type.encode("utf-8")],
            ),
        }
    )

    good_version = just(1)
    bad_version = one_of(
        text(),
        lists(integers()),
        integers(max_value=0),
        integers(min_value=2),
    )

    good_sizes = lists(integers(min_value=0))
    bad_sizes = one_of(
        integers(),
        text(),
        lists(text(), min_size=1),
        dictionaries(text(), text()),
        lists(integers(max_value=-1), min_size=1),
    )

    good_data = fixed_dictionaries(
        {
            "version": good_version,
            "sizes": good_sizes,
        }
    ).map(dumps_utf8)

    bad_data_version = fixed_dictionaries(
        {
            "version": bad_version,
            "sizes": good_sizes,
        }
    ).map(dumps_utf8)

    bad_data_sizes = fixed_dictionaries(
        {
            "version": good_version,
            "sizes": bad_sizes,
        }
    ).map(dumps_utf8)

    bad_data_other = dictionaries(
        text(),
        integers(),
    ).map(dumps_utf8)

    bad_data_junk = binary()

    good_fields = {
        "method": good_methods,
        "headers": good_headers,
        "data": good_data,
    }

    bad_choices = [
        ("method", bad_methods),
        ("headers", bad_headers),
        ("data", bad_data_version),
        ("data", bad_data_sizes),
        ("data", bad_data_other),
        ("data", bad_data_junk),
    ]

    def merge(fields, key, value):
        fields = fields.copy()
        fields[key] = value
        return fields

    return sampled_from(bad_choices,).flatmap(
        lambda bad_choice: builds(Request, **merge(good_fields, *bad_choice)),
    )


class CalculatePriceTests(TestCase):
    """
    Tests relating to ``/calculate-price`` as implemented by the
    ``_zkapauthorizer.resource`` module.
    """

    url = b"http://127.0.0.1/calculate-price"

    @given(
        tahoe_configs(),
        api_auth_tokens(),
        bad_calculate_price_requests(),
    )
    def test_bad_request(self, get_config, api_auth_token, bad_request):
        """
        When approached with:

          * a method other than POST
          * a content-type other than **application/json**
          * a request body which is not valid JSON
          * a JSON request body without version and sizes properties
          * a JSON request body without a version of 1
          * a JSON request body with other properties
          * or a JSON request body with sizes other than a list of integers

        response code is not in the 200 range.
        """
        config = get_config_with_api_token(
            self.useFixture(TempDir()),
            get_config,
            api_auth_token,
        )
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)
        self.assertThat(
            authorized_request(
                api_auth_token,
                agent,
                bad_request.method,
                self.url,
                headers=bad_request.headers,
                data=BytesIO(bad_request.data),
            ),
            succeeded(
                matches_response(
                    code_matcher=MatchesAny(
                        # It is fine to signal client errors
                        between(400, 499),
                        # It is fine to say we didn't implement the request
                        # method (I guess - Twisted Web sort of forces it on
                        # us, I'd rather have NOT ALLOWED for this case
                        # instead...).  We don't want INTERNAL SERVER ERROR
                        # though.
                        Equals(NOT_IMPLEMENTED),
                    ),
                ),
            ),
        )

    @given(
        tuples(
            # Make the share encoding parameters easily accessible without
            # going through the Tahoe-LAFS configuration.
            share_parameters(),
            # Same goes for the minimum lease time remaining configuration.
            posix_timestamps().map(int),
        ).flatmap(
            lambda share_and_lease_time: tuples(
                just(share_and_lease_time),
                direct_tahoe_configs(
                    zkapauthz_v2_configuration=client_dummyredeemer_configurations(
                        min_times_remaining=just(share_and_lease_time[1]),
                    ),
                    shares=just(share_and_lease_time[0]),
                ),
            ),
        ),
        api_auth_tokens(),
        lists(integers(min_value=0)),
    )
    def test_calculated_price(self, encoding_params_and_config, api_auth_token, sizes):
        """
        A well-formed request returns the price in ZKAPs as an integer and the
        storage period (the minimum allowed) that they pay for.
        """
        (encoding_params, min_time_remaining), config = encoding_params_and_config
        shares_needed, shares_happy, shares_total = encoding_params
        add_api_token_to_config(
            self.useFixture(TempDir()).join("tahoe"),
            config,
            api_auth_token,
        )
        root = root_from_config(config, datetime.now)
        agent = RequestTraversalAgent(root)

        expected_price = PriceCalculator(
            shares_needed=shares_needed,
            shares_total=shares_total,
            pass_value=get_configured_pass_value(config),
        ).calculate(sizes)

        self.assertThat(
            authorized_request(
                api_auth_token,
                agent,
                b"POST",
                self.url,
                headers={b"content-type": [b"application/json"]},
                data=BytesIO(dumps_utf8({"version": 1, "sizes": sizes})),
            ),
            succeeded(
                matches_response(
                    code_matcher=Equals(OK),
                    headers_matcher=application_json(),
                    body_matcher=AfterPreprocessing(
                        loads,
                        Equals(
                            {
                                "price": expected_price,
                                "period": 60 * 60 * 24 * 31 - min_time_remaining,
                            }
                        ),
                    ),
                ),
            ),
        )


def application_json():
    return AfterPreprocessing(
        lambda h: h.getRawHeaders("content-type"),
        Equals(["application/json"]),
    )


def json_content(response):
    reading = readBody(response)
    reading.addCallback(loads)
    return reading


def ok_response(headers=None):
    return match_response(OK, headers, phrase=Equals(b"OK"))


def not_found_response(headers=None):
    return match_response(NOT_FOUND, headers)


def bad_request_response(headers=None):
    return match_response(BAD_REQUEST, headers)


def match_response(code, headers, phrase=Always()):
    if headers is None:
        headers = Always()
    return _MatchResponse(
        code=Equals(code),
        headers=headers,
        phrase=phrase,
    )


@attr.s
class _MatchResponse(object):
    code = attr.ib()
    headers = attr.ib()
    phrase = attr.ib()
    _details = attr.ib(default=attr.Factory(dict))

    def match(self, response):
        self._details.update(
            {
                "code": response.code,
                "headers": response.headers.getAllRawHeaders(),
            }
        )
        return MatchesStructure(
            code=self.code,
            headers=self.headers,
            phrase=self.phrase,
        ).match(response)

    def get_details(self):
        return self._details
