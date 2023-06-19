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


class NonRedeemerConfig(TypedDict):
    """
    ``[storageserver.plugins.privatestorageio-zkapauthz-v2]`` contents in
    the non-redeeming configuration.

    In this configuration vouchers are accepted for redemption but no
    redemption attempt will ever complete.
    """

    redeemer: Literal["non"]


# [storageserver.plugins.privatestorageio-zkapauthz-v2]`` contents in the
# dummy redeemer configuration.
#
# In this configuration vouchers are redeemed for values which are
# structurally valid but otherwise nonsense.
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
    """
    ``[storageserver.plugins.privatestorageio-zkapauthz-v2]`` contents in
    the double-spend error configuration.

    In this configuration vouchers are accepted for redemption but all
    redemption attempts fail with an "already redeemed" error.
    """

    redeemer: Literal["double-spend"]


class UnpaidRedeemerConfig(TypedDict):
    """
    ``[storageserver.plugins.privatestorageio-zkapauthz-v2]`` contents in
    the unpaid configuration.

    In this configuration vouchers are accepted for redemption but all
    redemption attempts fail with an "unpaid voucher" error.
    """

    redeemer: Literal["unpaid"]


class ErrorRedeemerConfig(TypedDict):
    """
    ``[storageserver.plugins.privatestorageio-zkapauthz-v2]`` contents in
    the generic error configuration.

    In this configuration vouchers are accepted for redemption but all
    redemption attempts fail with an unstructured error with the associated
    details.
    """

    redeemer: Literal["error"]
    details: str


# [storageserver.plugins.privatestorageio-zkapauthz-v2]`` contents in the
# production configuration.
#
# In this configuration vouchers are submitted to a remote "redemption server"
# (aka "payment server").
RistrettoRedeemerConfig = TypedDict(
    "RistrettoRedeemerConfig",
    {
        "redeemer": Literal["ristretto"],
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

# The contents of the [storageclient.plugins.privatestorageio-zkapauthz-v2]
# section of a client node's tahoe.cfg.
ClientConfig = Union[
    NonRedeemerConfig,
    DummyRedeemerConfig,
    DoubleSpendRedeemerConfig,
    UnpaidRedeemerConfig,
    ErrorRedeemerConfig,
    RistrettoRedeemerConfig,
]
