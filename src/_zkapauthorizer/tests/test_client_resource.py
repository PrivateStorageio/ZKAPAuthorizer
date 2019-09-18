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
from urllib import (
    quote,
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
    Voucher,
    VoucherStore,
    memory_connect,
)
from ..resource import (
    from_configuration,
)

from .strategies import (
    tahoe_configs,
    vouchers,
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


def root_from_config(config):
    """
    Create a client root resource from a Tahoe-LAFS configuration.

    :param _Config config: The Tahoe-LAFS configuration.

    :return IResource: The root client resource.
    """
    return from_configuration(
        config,
        VoucherStore.from_node_config(
            config,
            memory_connect,
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


    @given(tahoe_configs(), requests(just([u"voucher"])))
    def test_reachable(self, get_config, request):
        """
        A resource is reachable at the ``voucher`` child of a the resource
        returned by ``from_configuration``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config)
        self.assertThat(
            getChildForRequest(root, request),
            Provides([IResource]),
        )


    @given(tahoe_configs(), vouchers())
    def test_put_voucher(self, get_config, voucher):
        """
        When a voucher is ``PUT`` to ``VoucherCollection`` it is passed in to the
        redemption model object for handling and an ``OK`` response is
        returned.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config)
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
        root = root_from_config(config)
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
        root = root_from_config(config)
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
        root = root_from_config(config)
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


    @given(tahoe_configs(), vouchers())
    def test_get_known_voucher(self, get_config, voucher):
        """
        When a voucher is first ``PUT`` and then later a ``GET`` is issued for the
        same voucher then the response code is **OK** and details about the
        voucher are included in a json-encoded response body.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config)
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
                        json_content,
                        succeeded(
                            Equals(Voucher(voucher).marshal()),
                        ),
                    ),
                ),
            ),
        )

    @given(tahoe_configs(), lists(vouchers(), unique=True))
    def test_list_vouchers(self, get_config, vouchers):
        """
        A ``GET`` to the ``VoucherCollection`` itself returns a list of existing
        vouchers.
        """
        # Hypothesis causes our test case instances to be re-used many times
        # between setUp and tearDown.  Avoid re-using the same temporary
        # directory for every Hypothesis iteration because this test leaves
        # state behind that invalidates future iterations.
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"tahoe"), b"tub.port")
        root = root_from_config(config)
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
                            Equals({
                                u"vouchers": list(
                                    Voucher(voucher).marshal()
                                    for voucher
                                    in vouchers
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
