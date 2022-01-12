# -*- coding: utf-8 -*-
# Tahoe-LAFS -- secure, distributed storage grid
#
# Copyright © 2020 The Tahoe-LAFS Software Foundation
#
# Copyright 2019 PrivateStorage.io, LLC

"""
Tests for ``_zkapauthorizer.private``.
"""

from allmydata.test.web.matchers import has_response_code
from testtools import TestCase
from testtools.matchers import Equals
from testtools.twistedsupport import succeeded
from treq.client import HTTPClient
from treq.testing import RequestTraversalAgent
from twisted.web.http import NOT_FOUND, UNAUTHORIZED
from twisted.web.http_headers import Headers
from twisted.web.resource import Resource

from ..private import SCHEME, create_private_tree


class PrivacyTests(TestCase):
    """
    Tests for the privacy features of the resources created by ``create_private_tree``.
    """

    def setUp(self):
        self.token = b"abcdef"
        self.resource = create_private_tree(lambda: self.token, Resource())
        self.agent = RequestTraversalAgent(self.resource)
        self.client = HTTPClient(self.agent)
        return super(PrivacyTests, self).setUp()

    def _authorization(self, scheme, value):
        return Headers(
            {
                "authorization": [
                    "{} {}".format(scheme.decode("ascii"), value.decode("ascii")),
                ],
            }
        )

    def test_unauthorized(self):
        """
        A request without an *Authorization* header receives an *Unauthorized* response.
        """
        self.assertThat(
            self.client.head(b"http:///foo/bar"),
            succeeded(has_response_code(Equals(UNAUTHORIZED))),
        )

    def test_wrong_scheme(self):
        """
        A request with an *Authorization* header not containing the Tahoe-LAFS
        scheme receives an *Unauthorized* response.
        """
        self.assertThat(
            self.client.head(
                b"http:///foo/bar",
                headers=self._authorization(b"basic", self.token),
            ),
            succeeded(has_response_code(Equals(UNAUTHORIZED))),
        )

    def test_wrong_token(self):
        """
        A request with an *Authorization* header not containing the expected token
        receives an *Unauthorized* response.
        """
        self.assertThat(
            self.client.head(
                b"http:///foo/bar",
                headers=self._authorization(SCHEME, b"foo bar"),
            ),
            succeeded(has_response_code(Equals(UNAUTHORIZED))),
        )

    def test_authorized(self):
        """
        A request with an *Authorization* header containing the expected scheme
        and token does not receive an *Unauthorized* response.
        """
        self.assertThat(
            self.client.head(
                b"http:///foo/bar",
                headers=self._authorization(SCHEME, self.token),
            ),
            # It's a made up URL so we don't get a 200, either, but a 404.
            succeeded(has_response_code(Equals(NOT_FOUND))),
        )
