# Copyright 2020 PrivateStorage.io, LLC
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
Eliot field, message, and action definitions for ZKAPAuthorizer.
"""

from functools import wraps
from json import JSONEncoder
from typing import Any, Awaitable, Callable, Optional, TypeVar, cast

from allmydata.util.eliotutil import log_call_deferred as _log_call_deferred
from eliot import ActionType, Field, MessageType
from eliot import log_call as _log_call
from eliot import start_action
from eliot.json import EliotJSONEncoder
from eliot.testing import capture_logging as _capture_logging
from typing_extensions import ParamSpec
from ._types import JSON

PRIVACYPASS_MESSAGE = Field(
    "message",
    str,
    "The PrivacyPass request-binding data associated with a pass.",
)

INVALID_REASON = Field(
    "reason",
    str,
    "The reason given by the server for rejecting a pass as invalid.",
)

PASS_COUNT = Field(
    "count",
    int,
    "A number of passes.",
)

GET_PASSES = MessageType(
    "zkapauthorizer:get-passes",
    [PRIVACYPASS_MESSAGE, PASS_COUNT],
    "An attempt to spend passes is beginning.",
)

SPENT_PASSES = MessageType(
    "zkapauthorizer:spent-passes",
    [PASS_COUNT],
    "An attempt to spend passes has succeeded.",
)

INVALID_PASSES = MessageType(
    "zkapauthorizer:invalid-passes",
    [INVALID_REASON, PASS_COUNT],
    "An attempt to spend passes has found some to be invalid.",
)

RESET_PASSES = MessageType(
    "zkapauthorizer:reset-passes",
    [PASS_COUNT],
    "Some passes involved in a failed spending attempt have not definitely been spent and are being returned for future use.",
)

SIGNATURE_CHECK_FAILED = MessageType(
    "zkapauthorizer:storage-client:signature-check-failed",
    [PASS_COUNT],
    "Some passes the client tried to use were rejected for having invalid signatures.",
)

CALL_WITH_PASSES = ActionType(
    "zkapauthorizer:storage-client:call-with-passes",
    [PASS_COUNT],
    [],
    "A storage operation is being started which may spend some passes.",
)

CURRENT_SIZES = Field(
    "current_sizes",
    dict,
    "A dictionary mapping the numbers of existing shares to their existing sizes.",
)

TW_VECTORS_SUMMARY = Field(
    "tw_vectors_summary",
    dict,
    "A dictionary mapping share numbers from tw_vectors to test and write vector summaries.",
)

NEW_SIZES = Field(
    "new_sizes",
    dict,
    "A dictionary like that of CURRENT_SIZES but for the sizes computed for the shares after applying tw_vectors.",
)

NEW_PASSES = Field(
    "new_passes",
    int,
    "The number of passes computed as being required for the change in size.",
)

MUTABLE_PASSES_REQUIRED = MessageType(
    "zkapauthorizer:storage:mutable-passes-required",
    [CURRENT_SIZES, TW_VECTORS_SUMMARY, NEW_SIZES, NEW_PASSES],
    "Some number of passes has been computed as the cost of updating a mutable.",
)

T = TypeVar("T")
P = ParamSpec("P")
Q = ParamSpec("Q")

JSONT = TypeVar("JSONT", bound=JSON)

def log_call(
    action_type: Optional[str] = None,
    include_args: Optional[list[str]] = None,
    include_result: bool = True,
) -> Callable[[Callable[P, JSONT]], Callable[P, JSONT]]:
    return cast(
        Callable[[Callable[P, JSONT]], Callable[P, JSONT]],
        _log_call(
            action_type=action_type,
            include_args=include_args,
            include_result=include_result,
        ),
    )


def log_call_deferred(
    action_type: Optional[str] = None,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    return cast(
        Callable[[Callable[P, T]], Callable[P, T]],
        _log_call_deferred(action_type),
    )


def log_call_coroutine(
    action_type: str,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    def decorate_log_call_coroutine(
        f: Callable[P, Awaitable[T]]
    ) -> Callable[P, Awaitable[T]]:
        @wraps(f)
        async def logged_f(*a: P.args, **kw: P.kwargs) -> T:
            with start_action(action_type=action_type):
                return await f(*a, **kw)

        return logged_f

    return decorate_log_call_coroutine


def capture_logging(
    assertion: Any,
    *assertionArgs: Any,
    encoder_: JSONEncoder = EliotJSONEncoder,
    **assertionKwargs: Any,
) -> Callable[[Callable[P, T]], Callable[P, T]]:
    return cast(
        Callable[[Callable[P, T]], Callable[P, T]],
        _capture_logging(
            assertion, *assertionArgs, encoder_=encoder_, **assertionKwargs
        ),
    )
