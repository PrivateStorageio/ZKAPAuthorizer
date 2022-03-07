from math import isnan, nextafter

from attrs import define
from testtools.matchers import Mismatch


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
    # Sometimes a value is exactly an integer and may come out of some system
    # as an int instead of a float.  We can deal with that so let it through.
    # Provide an early error for any other types, though.
    if not isinstance(start, (int, float)) or not isinstance(goal, (int, float)):
        raise TypeError(f"requires ints or floats, got {start!r} and {goal!r} instead")

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
