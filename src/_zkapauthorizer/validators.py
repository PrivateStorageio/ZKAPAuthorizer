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
This module implements validators for ``attrs``-defined attributes.
"""

from typing import Callable, Protocol, TypeVar, Sequence
from base64 import b64decode
from datetime import datetime

from ._types import Attribute
from ._base64 import urlsafe_b64decode

_T = TypeVar("_T")

ValidatorType = Callable[[object, Attribute[_T], _T], None]

def returns_aware_datetime_validator(inst: object, attr: Attribute[Callable[[], datetime]], value: Callable[[], datetime]) -> None:
    """
    An attrs validator that verifies the attribute value is a function that
    returns a timezone-aware datetime instance for at least one call.
    """
    if is_aware_datetime(value()):
        return None
    # Is it really a TypeError and not a ValueError?  It doesn't matter and
    # also attrs converts anything we raise into a TypeError.
    raise TypeError(
        f"{attr.name!r} must return aware datetime instances (returned {value!r})"
    )


def is_aware_datetime(value: datetime) -> bool:
    """
    :return: ``True`` if and only iff the given value is a timezone-aware
        datetime instance.
    """
    return isinstance(value, datetime) and value.tzinfo is not None


def aware_datetime_validator(inst: object, attr: Attribute[datetime], value: datetime) -> None:
    """
    An attrs validator that verifies the attribute value is a timezone-aware
    datetime instance.
    """
    if is_aware_datetime(value):
        return None
    raise TypeError(f"{attr.name!r} must be an aware datetime instance (got {value!r})")


def is_base64_encoded(b64decode: Callable[[bytes], bytes] = b64decode) -> ValidatorType[bytes]:
    """
    Return an attrs validator that verifies that the attributes is a base64
    encoded byte string.
    """

    def validate_is_base64_encoded(inst: object, attr: Attribute[bytes], value: bytes) -> None:
        try:
            b64decode(value)
        except TypeError:
            raise TypeError(
                "{name!r} must be base64 encoded bytes, (got {value!r})".format(
                    name=attr.name,
                    value=value,
                ),
            )

    return validate_is_base64_encoded



def has_length(expected: int) -> ValidatorType[Sequence[_T]]:
    def validate_has_length(inst: object, attr: Attribute[Sequence[_T]], value: Sequence[_T]) -> None:
        if len(value) != expected:
            raise ValueError(
                "{name!r} must have length {expected}, instead has length {actual}".format(
                    name=attr.name,
                    expected=expected,
                    actual=len(value),
                ),
            )

    return validate_has_length


class Ordered(Protocol):
    def __gt__(self: _T, other: _T) -> bool:
        ...


def greater_than(expected: Ordered) -> ValidatorType[Ordered]:
    def validate_relation(inst: object, attr: Attribute[Ordered], value: Ordered) -> None:
        if value > expected:
            return None

        raise ValueError(
            "{name!r} must be greater than {expected}, instead it was {actual}".format(
                name=attr.name,
                expected=expected,
                actual=value,
            ),
        )

    return validate_relation

def bounded_integer(min_bound: int) -> ValidatorType[int]:
    def validator(inst: object, attr: Attribute[int], value: int) -> None:
        """
        An attrs validator which checks an integer value to make sure it
        greater than some minimum bound.
        """
        if not isinstance(value, int):
            raise ValueError(
                f"{attr.name} must be an integer, instead it was {type(value)}",
            )
        if not (value > min_bound):
            raise ValueError(
                f"{attr.name} must be greater than {min_bound}, instead it was {value}",
            )

        return None
    return validator

positive_integer = bounded_integer(0)
non_negative_integer = bounded_integer(-1)

def base64_bytes(length: int) -> ValidatorType[bytes]:
    def validator(inst: object, attr: Attribute[bytes], value: bytes) -> None:
        if not isinstance(value, bytes):
            raise ValueError(
                f"{attr.name} must be bytes, instead it was {type(value)}",
            )
        if not is_base64_encoded(urlsafe_b64decode):
            raise ValueError(
                f"{attr.name} must be base64 encoded data",
            )

        if len(value) != length:
            raise ValueError(
                f"{attr.name} value must have length {length}, not {len(value)}",
            )

        return None
    return validator
