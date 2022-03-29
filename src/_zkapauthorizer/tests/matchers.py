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
Testtools matchers useful for the test suite.
"""

__all__ = [
    "Provides",
    "raises",
    "returns",
    "matches_version_dictionary",
    "between",
    "leases_current",
    "equals_database",
    "matches_float_within_distance",
]

from datetime import datetime
from json import loads
from typing import Generic, TypeVar, Union

import attr
from testtools.matchers import (
    AfterPreprocessing,
    AllMatch,
    Always,
    ContainsDict,
    Equals,
    GreaterThan,
    LessThan,
)
from testtools.matchers import Matcher as _Matcher
from testtools.matchers import (
    MatchesAll,
    MatchesAny,
    MatchesDict,
    MatchesSetwise,
    MatchesStructure,
    Mismatch,
)
from testtools.twistedsupport import succeeded
from treq import content
from twisted.web.http_headers import Headers

from ..model import Pass
from ..server.spending import _SpendingData
from ._exception import raises
from ._float_matchers import matches_float_within_distance
from ._sql_matchers import equals_database

_T = TypeVar("_T")


class Matcher(_Matcher, Generic[_T]):
    """
    A generic version of ``_Matcher``.
    """


@attr.s
class Provides(object):
    """
    Match objects that provide all of a list of Zope Interface interfaces.
    """

    interfaces = attr.ib(validator=attr.validators.instance_of(list))

    def match(self, obj):
        missing = set()
        for iface in self.interfaces:
            if not iface.providedBy(obj):
                missing.add(iface)
        if missing:
            return Mismatch(
                "{} does not provide expected {}".format(
                    obj,
                    ", ".join(str(iface) for iface in missing),
                )
            )


def matches_version_dictionary():
    """
    Match the dictionary returned by Tahoe-LAFS'
    ``RIStorageServer.get_version`` which is also the dictionary returned by
    our own ``RIPrivacyPassAuthorizedStorageServer.get_version``.
    """
    return ContainsDict(
        {
            # It has these two top-level keys, at least.  Try not to be too
            # fragile by asserting much more than that they are present.
            b"application-version": Always(),
            b"http://allmydata.org/tahoe/protocols/storage/v1": Always(),
        }
    )


def returns(matcher):
    """
    Matches a no-argument callable that returns a value matched by the given
    matcher.
    """
    return _Returns(matcher)


class _Returns(_Matcher):
    def __init__(self, result_matcher):
        self.result_matcher = result_matcher

    def match(self, matchee):
        return self.result_matcher.match(matchee())

    def __str__(self):
        return "Returns({})".format(self.result_matcher)


def greater_or_equal(v):
    """
    Matches a value greater than or equal to ``v``.
    """
    return MatchesAny(GreaterThan(v), Equals(v))


def lesser_or_equal(v):
    """
    Matches a value less than or equal to ``v``.
    """
    return MatchesAny(LessThan(v), Equals(v))


def between(low, high):
    """
    Matches a value in the range [low, high].
    """
    return MatchesAll(
        greater_or_equal(low),
        lesser_or_equal(high),
    )


def leases_current(relevant_storage_indexes, now, min_lease_remaining):
    """
    Return a matcher on a ``DummyStorageServer`` instance which matches
    servers for which the leases on the given storage indexes do not expire
    before ``min_lease_remaining``.
    """

    def get_relevant_stats(storage_server):
        for (storage_index, shares) in storage_server.buckets.items():
            if storage_index in relevant_storage_indexes:
                for (sharenum, stat) in shares.items():
                    yield stat

    return AfterPreprocessing(
        # Get share stats for storage indexes we should have
        # visited and maintained.
        lambda storage_server: list(get_relevant_stats(storage_server)),
        AllMatch(
            AfterPreprocessing(
                # Lease expiration for anything visited must be
                # further in the future than min_lease_remaining,
                # either because it had time left or because we
                # renewed it.
                lambda share_stat: datetime.utcfromtimestamp(
                    share_stat.lease_expiration
                ),
                GreaterThan(now + min_lease_remaining),
            ),
        ),
    )


def even():
    """
    Matches even integers.
    """
    return AfterPreprocessing(
        lambda n: n % 2,
        Equals(0),
    )


def odd():
    """
    Matches odd integers.
    """
    return AfterPreprocessing(
        lambda n: n % 2,
        Equals(1),
    )


def matches_response(
    code_matcher: Matcher[int] = Always(),
    headers_matcher: Matcher[Headers] = Always(),
    body_matcher: Matcher[bytes] = Always(),
):
    """
    Match a Treq response object with certain code and body.

    :param code_matcher: A matcher to apply to the response code.

    :param headers_matcher: A matcher to apply to the response headers (a
        ``twisted.web.http_headers.Headers`` instance).

    :param body_matcher: A matcher to apply to the response body.

    :return: A matcher.
    """
    return MatchesAll(
        MatchesStructure(
            code=code_matcher,
            headers=headers_matcher,
        ),
        AfterPreprocessing(
            lambda response: content(response),
            succeeded(body_matcher),
        ),
    )


def matches_spent_passes(
    public_key_hash: bytes, spent_passes: list[Pass]
) -> Matcher[_SpendingData]:
    """
    Returns a matcher for _SpendingData that checks whether the
    spent pass match the given public key and passes.
    """
    return AfterPreprocessing(
        lambda spending_recorder: spending_recorder.spent_tokens,
        MatchesDict(
            {
                public_key_hash: MatchesSetwise(
                    *[Equals(pass_.preimage) for pass_ in spent_passes]
                )
            }
        ),
    )


def matches_json(matcher=Always()):
    """
    Return a matcher for a JSON string which can be decoded to an object
    matched by the given matcher.
    """

    class Matcher:
        def match(self, s):
            try:
                value = loads(s)
            except Exception as e:
                return Mismatch(f"Failed to decode {str(s)[:80]!r}: {e}")

            return matcher.match(value)

    return Matcher()


def matches_capability(type_matcher):
    """
    Return a matcher for a unicode string representing a Tahoe-LAFS capability
    that has a type matched by ``type_matcher``.
    """

    def get_cap_type(cap: str) -> Union[str, None]:
        if not isinstance(cap, str):
            raise Exception(f"expected str cap, got {cap!r}")
        pieces = cap.split(":")
        if len(pieces) > 1 and pieces[0] == "URI":
            return pieces[1]
        return None

    return AfterPreprocessing(
        get_cap_type,
        type_matcher,
    )
