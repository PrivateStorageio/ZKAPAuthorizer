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

import attr

from .._base64 import (
    urlsafe_b64decode,
)

from json import (
    dumps,
    loads,
)
from io import (
    BytesIO,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    MatchesStructure,
    MatchesAll,
    AfterPreprocessing,
    Equals,
    Always,
)
from testtools.twistedsupport import (
    CaptureTwistedLogs,
    succeeded,
)
from testtools.content import (
    text_content,
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
    PaymentReferenceStore,
    memory_connect,
)
from ..resource import (
    from_configuration,
)

from .strategies import (
    tahoe_configs,
    client_configurations,
    payment_reference_numbers,
    requests,
)
from .matchers import (
    Provides,
)

# Helper to work-around https://github.com/twisted/treq/issues/161
def uncooperator(started=True):
    return Cooperator(
        # Don't stop consuming the iterator until it's done.
        terminationPredicateFactory=lambda: lambda: False,
        scheduler=lambda what: (what(), object())[1],
        started=started,
    )



tahoe_configs_with_client_config = tahoe_configs(storage_client_plugins={
    u"privatestorageio-satauthz-v1": client_configurations(),
})

def is_not_json(bytestring):
    try:
        loads(bytestring)
    except:
        return True
    return False

def not_payment_reference_numbers():
    return text().filter(
        lambda t: (
            # exclude / because it changes url dispatch and makes tests fail
            # differently.
            u"/" not in t and not is_urlsafe_base64(t)
        ),
    )


def is_urlsafe_base64(text):
    try:
        urlsafe_b64decode(text)
    except:
        return False
    return True


def invalid_bodies():
    """
    Build byte strings that ``PUT /payment-reference-number`` considers
    invalid.
    """
    return one_of(
        # The wrong key but the right kind of value.
        fixed_dictionaries({
            u"some-key": payment_reference_numbers(),
        }).map(dumps),
        # The right key but the wrong kind of value.
        fixed_dictionaries({
            u"payment-reference-number": one_of(
                integers(),
                not_payment_reference_numbers(),
            ),
        }).map(dumps),
        fixed_dictionaries({
            u"payment-reference-number": integers(),
        }).map(dumps),
        # Not even JSON
        binary().filter(is_not_json),
    )


def root_from_config(config):
    return from_configuration(
        config,
        PaymentReferenceStore.from_node_config(
            config,
            memory_connect,
        ),
    )


class PaymentReferenceNumberTests(TestCase):
    """
    Tests relating to ``/payment-reference-number`` as implemented by the
    ``_secureaccesstokenauthorizer.resource`` module and its handling of
    payment reference numbers (PRNs).
    """
    def setUp(self):
        super(PaymentReferenceNumberTests, self).setUp()
        self.useFixture(CaptureTwistedLogs())


    @given(tahoe_configs_with_client_config, requests(just([u"payment-reference-number"])))
    def test_reachable(self, get_config, request):
        """
        A resource is reachable at the ``payment-reference-number`` child of a the
        resource returned by ``from_configuration``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe.ini"), b"tub.port")
        root = root_from_config(config)
        self.assertThat(
            getChildForRequest(root, request),
            Provides([IResource]),
        )


    @given(tahoe_configs_with_client_config, payment_reference_numbers())
    def test_put_prn(self, get_config, prn):
        """
        When a PRN is sent in a ``PUT`` to ``PaymentReferenceNumberCollection`` it
        is passed in to the PRN redemption model object for handling and an
        ``OK`` response is returned.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe.ini"), b"tub.port")
        root = root_from_config(config)
        agent = RequestTraversalAgent(root)
        producer = FileBodyProducer(
            BytesIO(dumps({u"payment-reference-number": prn})),
            cooperator=uncooperator(),
        )
        requesting = agent.request(
            b"PUT",
            b"http://127.0.0.1/payment-reference-number",
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

    @given(tahoe_configs_with_client_config, invalid_bodies())
    def test_put_invalid_body(self, get_config, body):
        """
        If the body of a ``PUT`` to ``PaymentReferenceNumberCollection`` does not
        consist of an object with a single *payment-reference-number* property
        then the response is *BAD REQUEST*.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe.ini"), b"tub.port")
        root = root_from_config(config)
        agent = RequestTraversalAgent(root)
        producer = FileBodyProducer(
            BytesIO(body),
            cooperator=uncooperator(),
        )
        requesting = agent.request(
            b"PUT",
            b"http://127.0.0.1/payment-reference-number",
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

    @given(tahoe_configs_with_client_config, payment_reference_numbers())
    def test_get_invalid_prn(self, get_config, prn):
        """
        When a syntactically invalid PRN is requested with a ``GET`` to a child of
        ``PaymentReferenceNumberCollection`` the response is **BAD REQUEST**.
        """
        tempdir = self.useFixture(TempDir())
        not_prn = prn[1:]
        config = get_config(tempdir.join(b"tahoe.ini"), b"tub.port")
        root = root_from_config(config)
        agent = RequestTraversalAgent(root)
        requesting = agent.request(
            b"GET",
            u"http://127.0.0.1/payment-reference-number/{}".format(not_prn).encode("utf-8"),
        )
        self.assertThat(
            requesting,
            succeeded(
                bad_request_response(),
            ),
        )


    @given(tahoe_configs_with_client_config, payment_reference_numbers())
    def test_get_unknown_prn(self, get_config, prn):
        """
        When a PRN is requested with a ``GET`` to a child of
        ``PaymentReferenceNumberCollection`` the response is **NOT FOUND** if
        the PRN hasn't previously been submitted with a ``PUT``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe.ini"), b"tub.port")
        root = root_from_config(config)
        agent = RequestTraversalAgent(root)
        requesting = agent.request(
            b"GET",
            u"http://127.0.0.1/payment-reference-number/{}".format(prn).encode("ascii"),
        )
        self.assertThat(
            requesting,
            succeeded(
                not_found_response(),
            ),
        )


    @given(tahoe_configs_with_client_config, payment_reference_numbers())
    def test_get_known_prn(self, get_config, prn):
        """
        When a PRN is first ``PUT`` and then later a ``GET`` is issued for the
        same PRN then the response code is **OK** and details about the PRN
        are included in a json-encoded response body.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe.ini"), b"tub.port")
        root = root_from_config(config)
        agent = RequestTraversalAgent(root)

        producer = FileBodyProducer(
            BytesIO(dumps({u"payment-reference-number": prn})),
            cooperator=uncooperator(),
        )
        putting = agent.request(
            b"PUT",
            b"http://127.0.0.1/payment-reference-number",
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
            u"http://127.0.0.1/payment-reference-number/{}".format(prn).encode("ascii"),
        )

        self.assertThat(
            getting,
            succeeded(
                MatchesAll(
                    ok_response(headers=application_json()),
                    AfterPreprocessing(
                        json_content,
                        succeeded(
                            Equals({
                                u"version": 1,
                                u"number": prn,
                            }),
                        ),
                    ),
                ),
            ),
        )

    @given(tahoe_configs_with_client_config, lists(payment_reference_numbers(), unique=True))
    def test_list_prns(self, get_config, prns):
        """
        A ``GET`` to the ``PaymentReferenceNumberCollection`` itself returns a
        list of existing payment reference numbers.
        """
        # Hypothesis causes our test case instances to be re-used many times
        # between setUp and tearDown.  Avoid re-using the same temporary
        # directory for every Hypothesis iteration because this test leaves
        # state behind that invalidates future iterations.
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe.ini"), b"tub.port")
        root = root_from_config(config)
        agent = RequestTraversalAgent(root)

        note("{} PRNs".format(len(prns)))

        for prn in prns:
            producer = FileBodyProducer(
                BytesIO(dumps({u"payment-reference-number": prn})),
                cooperator=uncooperator(),
            )
            putting = agent.request(
                b"PUT",
                b"http://127.0.0.1/payment-reference-number",
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
            b"http://127.0.0.1/payment-reference-number",
        )

        self.assertThat(
            getting,
            succeeded(
                MatchesAll(
                    ok_response(headers=application_json()),
                    AfterPreprocessing(
                        json_content,
                        succeeded(
                            Equals({
                                u"payment-reference-numbers": list(
                                    {u"version": 1, u"number": prn}
                                    for prn
                                    in prns
                                ),
                            }),
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
