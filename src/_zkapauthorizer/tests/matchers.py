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
]

from datetime import datetime
from json import loads
from math import isnan, nextafter

import attr
from attrs import define
from testtools.matchers import (
    AfterPreprocessing,
    AllMatch,
    Always,
    ContainsDict,
    Equals,
    GreaterThan,
    LessThan,
    Matcher,
    MatchesAll,
    MatchesAny,
    MatchesDict,
    MatchesSetwise,
    MatchesStructure,
    Mismatch,
)
from testtools.twistedsupport import succeeded
from treq import content

from ..model import Pass
from ..server.spending import _SpendingData
from ._exception import raises


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


class _Returns(Matcher):
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
    code_matcher=Always(), headers_matcher=Always(), body_matcher=Always()
):
    """
    Match a Treq response object with certain code and body.

    :param Matcher code_matcher: A matcher to apply to the response code.

    :param Matcher headers_matcher: A matcher to apply to the response headers
        (a ``twisted.web.http_headers.Headers`` instance).

    :param Matcher body_matcher: A matcher to apply to the response body.

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


def matches_spent_passes(public_key_hash, spent_passes):
    # type: (bytes, list[Pass]) -> Matcher[_SpendingData]
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

    def get_cap_type(cap: str) -> str:
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


def unit_of_least_precision_distance(
    start: float, goal: float, max_distance: int
) -> int:
    """
    Compute the distance from ``start`` to ``goal`` in terms of floating point
    "unit of least precision" ("ULP").

    This is roughly how many floating point values there are between ``start``
    and ``goal``.

    :return: The distance.

    :raise ValueError: If the distance is greater than ``max_distance``.  The
        cost of the distance calculation is linear on the size of the distance
        and the distance between two floating point values could be almost 2
        ** 64.  You probably want to limit the amount of work done to a much
        smaller distance.
    """
    if isnan(start) or isnan(goal):
        raise ValueError("Cannot find distance to or from NaN")

    if start == goal:
        return 0

    distance = 0
    while distance < max_distance:
        distance += 1
        start = nextafter(start, goal)
        if start == goal:
            return distance

    raise ValueError(f"{start} is more than {distance} from {goal}")


@define
class _MatchFloatWithinDistance(object):
    """
    See ``matches_float_within_distance``.
    """

    reference: float
    distance: int
    max_distance: int

    def match(self, actual):
        try:
            distance = unit_of_least_precision_distance(
                self.reference, actual, self.max_distance
            )
        except ValueError:
            return Mismatch(
                f"float {actual} is more than {self.max_distance} "
                f"from {self.reference} - search abandoned "
                f"(allowed distance is {self.distance})",
            )
        else:
            if distance > self.distance:
                return Mismatch(
                    f"distance from {self.reference} "
                    f"to {actual} "
                    f"is {distance}, "
                    f"greater than allowed distance of {self.distance}",
                )
        return None


def matches_float_within_distance(
    reference: float, distance: int, max_distance: int = 100
):
    """
    Matches a floating point value that is no more than a given distance in
    "unit of least precision" steps of a reference value.

    :param reference: The reference floating point value.
    :param distance: The maximum allowed distance to a matched value.

    :param max_distance: The maximum distance to search (to try to provide
        extra information when the match fails).
    """

    return _MatchFloatWithinDistance(reference, distance, max_distance)
