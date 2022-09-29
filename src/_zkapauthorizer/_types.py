# Copyright 2022 PrivateStorage.io, LLC
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
Re-usable type definitions for ZKAPAuthorizer.
"""

from datetime import datetime
from typing import (
    TYPE_CHECKING,
    Callable,
    Generic,
    Mapping,
    Sequence,
    TypedDict,
    TypeVar,
    Union,
)

from attrs import Attribute as _Attribute
from typing_extensions import Literal

GetTime = Callable[[], datetime]

_T = TypeVar("_T")

if TYPE_CHECKING:
    Attribute = _Attribute
else:

    class Attribute(_Attribute, Generic[_T]):
        pass


# mypy does not support recursive types so we can't say much about what's in
# the containers here.
JSON = Union[None, int, float, str, Sequence, Mapping]

# The contents of the [storageserver.plugins.privatestorageio-zkapauthz-v2]
# section of a storage server's tahoe.cfg.
ServerConfig = TypedDict(
    "ServerConfig",
    {
        "pass-value": str,
        "ristretto-issuer-root-url": str,
        "ristretto-signing-key-path": str,
        "prometheus-metrics-path": str,
        "prometheus-metrics-interval": str,
    },
    total=False,
)

# The contents of the [storageclient.plugins.privatestorageio-zkapauthz-v2]
# section of a client node's tahoe.cfg.
class NonRedeemerConfig(TypedDict):
    redeemer: Literal["non"]


DummyRedeemerConfig = TypedDict(
    "DummyRedeemerConfig",
    {
        "redeemer": Literal["dummy"],
        "issuer-public-key": str,
        "allowed-public-keys": str,
        # XXX All the other types should have these too but it's so tedious...
        "lease.crawl-interval.mean": str,
        "lease.crawl-interval.range": str,
        "lease.min-time-remaining": str,
    },
)


class DoubleSpendRedeemerConfig(TypedDict):
    redeemer: Literal["double-spend"]


class UnpaidRedeemerConfig(TypedDict):
    redeemer: Literal["unpaid"]


class ErrorRedeemerConfig(TypedDict):
    redeemer: Literal["error"]
    details: str


RistrettoRedeemerConfig = TypedDict(
    "RistrettoRedeemerConfig",
    {
        "redeemer": Literal["ristretto"],
        "issuer-public-key": str,
        "ristretto-issuer-root-url": str,
        "pass-value": str,
        "default-token-count": str,
        "allowed-public-keys": str,
        "lease.crawl-interval.mean": str,
        "lease.crawl-interval.range": str,
        "lease.min-time-remaining": str,
    },
    total=False,
)

ClientConfig = Union[
    NonRedeemerConfig,
    DummyRedeemerConfig,
    DoubleSpendRedeemerConfig,
    UnpaidRedeemerConfig,
    ErrorRedeemerConfig,
    RistrettoRedeemerConfig,
]
