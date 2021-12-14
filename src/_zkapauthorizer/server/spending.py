
import json

from typing import Any

import attr
from challenge_bypass_ristretto import PublicKey
from eliot import start_action
from eliot.twisted import inline_callbacks
from prometheus_client import CollectorRegistry, Counter
from treq.client import HTTPClient
from twisted.internet.interfaces import IReactorTime
from twisted.python.url import URL
from twisted.web import http
from twisted.web.client import Agent
from zope.interface import Interface, implementer

from ..eliot import register_attr_exception


@register_attr_exception
@attr.s(auto_exc=True)
class UnexpectedResponse(Exception):
    """
    The issuer responded in an unexpected and unhandled way.
    """

    code = attr.ib()
    body = attr.ib()


class ISpender(Interface):
    """
    An ``ISpender`` can records spent ZKAPs and reports double spends.
    """

    def mark_as_spent(public_key, passes):
        # type: (PublicKey, list[bytes]) -> None
        """
        Record the given ZKAPs (associated to the given public key as having
        been spent.

        This does *not* report errors and should only be used in cases when
        recording spending that has already happened. This can be because
        we could not contact the spending service when they were spent, or
        because we can't yet check before making changes to the node.
        """


@attr.s
class _SpendingData(object):
    spent_tokens = attr.ib(init=False, factory=dict)

    def reset(self):
        self.spent_tokens.clear()


@implementer(ISpender)
@attr.s
class RecordingSpender(object):
    """
    An in-memory :py:`ISpender` implementation that exposes the spent tokens
    for testing purposes.
    """

    _recorder = attr.ib(validator=attr.validators.instance_of(_SpendingData))

    @classmethod
    def make(cls):
        # type: () -> (_SpendingData, ISpender)
        recorder = _SpendingData()
        return recorder, cls(recorder)

    def mark_as_spent(self, public_key, passes):
        self._recorder.spent_tokens.setdefault(public_key.encode_base64(), []).extend(
            passes
        )


def counter_attr(name, description, labels=()):

    attrib = attr.ib(
        init=False,
        metadata={
            "metric-labels": labels,
            "metric-name": name,
        },
    )

    @attrib.default
    def make_counter(self):
        return Counter(name, description, labelnames=labels, registry=self._registry)

    return attrib


@implementer(ISpender)
@attr.s
class Spender(object):
    _treq = attr.ib(validator=attr.validators.instance_of(HTTPClient))
    _api_root = attr.ib(validator=attr.validators.instance_of(URL))
    _registry = attr.ib()

    @classmethod
    def make(cls, config, reactor, registry):
        # type: (dict[str, Any], IReactorTime, CollectorRegistry) -> ISpender
        spending_service_url = config.pop("spending-service-url")
        return cls(
            HTTPClient(Agent(reactor)),
            URL.from_text(spending_service_url),
            registry,
        )

    @inline_callbacks
    def ping(self):
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
    def mark_as_spent(self, public_key, passes):
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
                            "tokens": {public_key.encode_base64(): passes},
                            # "force": True,
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
