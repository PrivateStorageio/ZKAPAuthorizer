# -*- coding: utf-8 -*-
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
A client for the ZKAP Spending Service, which records spent ZKAPs.
"""

from __future__ import annotations

import json
from typing import Any

import attrs
from challenge_bypass_ristretto import PublicKey
from eliot import start_action
from eliot.twisted import inline_callbacks
from hyperlink import URL
from prometheus_client import CollectorRegistry, Counter
from treq.client import HTTPClient
from treq.testing import StubTreq
from twisted.internet.interfaces import IReactorTime
from twisted.web import http
from twisted.web.client import Agent
from zope.interface import Interface, implementer

from ..eliot import register_attr_exception


@register_attr_exception
@attrs.define
class UnexpectedResponse(Exception):
    """
    The issuer responded in an unexpected and unhandled way.
    """

    code: int
    body: bytes


class ISpender(Interface):
    """
    An ``ISpender`` can records spent ZKAPs and reports double spends.
    """

    def mark_as_spent(public_key, token_preimages):
        # type: (PublicKey, list[bytes]) -> None
        """
        Record the given ZKAPs (associated to the given public key as having
        been spent.

        This does *not* report errors and should only be used in cases when
        recording spending that has already happened. This can be because
        we could not contact the spending service when they were spent, or
        because we can't yet check before making changes to the node.
        """


def counter_attr(name, description, labels=()):
    """
    Return an attrs attribute that is a prometheus :py:`Counter` metric registered
    with the ``_registry`` on the instance.
    """
    attrib = attrs.field(
        init=False,
        metadata={
            "metric-labels": labels,
            "metric-name": "{}".format(name),
        },
    )

    @attrib.default
    def make_counter(self):
        return Counter(name, description, labelnames=labels, registry=self._registry)

    return attrib


@implementer(ISpender)
@attrs.define
class Spender(object):
    """
    An :py:`ISpender` that talks to a ZKAP Spending Service.
    """

    _treq: HTTPClient = attrs.field(
        validator=attrs.validators.instance_of((HTTPClient, StubTreq))
    )
    _api_root: URL = attrs.field(validator=attrs.validators.instance_of(URL))
    _registry: CollectorRegistry = attrs.field()

    @classmethod
    def make(
        cls, config: dict[str, Any], reactor: IReactorTime, registry: CollectorRegistry
    ) -> ISpender:
        spending_service_url = config.pop("spending-service-url")
        return cls(
            HTTPClient(Agent(reactor)),
            URL.from_text(spending_service_url),
            registry,
        )

    @inline_callbacks
    def ping(self) -> None:
        response = yield self._treq.get(self._api_root.child("v1", "_ping").to_text())

        response_body = yield response.content()
        if response.code != http.OK:
            raise Exception("Not ok")

        try:
            result = json.loads(response_body)
        except ValueError:
            raise UnexpectedResponse(response.code, response_body)

        if result.get("status") != "ok":
            raise Exception("Didn't get ping from spending service.")

    SPEND_PASSES = counter_attr("zkapauthorizer_spend_passes_total", "FIXME: DESC")
    SPEND_PASSES_ERRORS = counter_attr(
        "zkapauthorizer_spend_passes_error_total",
        "FIXME: DESC",
        labels=("reason", "code"),
    )
    SPEND_PASSES_FAILURES = counter_attr(
        "zkapauthorizer_spend_passes_failures_total",
        "FIXME: DESC",
    )
    SPEND_PASSES_SUCCESSES = counter_attr(
        "zkapauthorizer_spend_passes_successes_total",
        "FIXME: DESC",
    )

    @inline_callbacks
    def mark_as_spent(self, public_key, token_preimages):
        """
        Takes a dictionary mapping public keys to lists of spend tokens,
        and reports them as spent.
        """
        self.SPEND_PASSES.inc()
        try:
            with start_action(
                action_type="zkapauthorizer:server:spend-passes"
            ) as action:
                response = yield self._treq.post(
                    self._api_root.child("v1", "spend").to_text(),
                    json.dumps(
                        {
                            "tokens": {
                                public_key.encode_base64().decode("ascii"): [
                                    token_preimage.decode("ascii")
                                    for token_preimage in token_preimages
                                ]
                            },
                            "force": True,
                        }
                    ),
                    headers={b"content-type": b"application/json"},
                )
                try:
                    result = yield response.json()
                except:
                    raise UnexpectedResponse(response.code, "")

                if response.code != http.OK:
                    self.SPEND_PASSES_ERRORS.labels(
                        reason=result["reason"], code=response.code
                    ).inc()
                else:
                    action.add_success_fields(code=response.code, body=result)
                    self.SPEND_PASSES_SUCCESSES.inc()

        except Exception:
            self.SPEND_PASSES_FAILURES.inc()
            # eliot will have logged any exception above.  Since we want to
            # fail open, we consume exceptions here.


get_spender = Spender.make
