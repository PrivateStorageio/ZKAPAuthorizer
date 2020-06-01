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

from __future__ import (
    absolute_import,
)

from eliot import (
    Field,
    MessageType,
    ActionType,
)

PRIVACYPASS_MESSAGE = Field(
    u"message",
    unicode,
    u"The PrivacyPass request-binding data associated with a pass.",
)

INVALID_REASON = Field(
    u"reason",
    unicode,
    u"The reason given by the server for rejecting a pass as invalid.",
)

PASS_COUNT = Field(
    u"count",
    int,
    u"A number of passes.",
)

GET_PASSES = MessageType(
    u"zkapauthorizer:get-passes",
    [PRIVACYPASS_MESSAGE, PASS_COUNT],
    u"An attempt to spend passes is beginning.",
)

SPENT_PASSES = MessageType(
    u"zkapauthorizer:spent-passes",
    [PASS_COUNT],
    u"An attempt to spend passes has succeeded.",
)

INVALID_PASSES = MessageType(
    u"zkapauthorizer:invalid-passes",
    [INVALID_REASON, PASS_COUNT],
    u"An attempt to spend passes has found some to be invalid.",
)

RESET_PASSES = MessageType(
    u"zkapauthorizer:reset-passes",
    [PASS_COUNT],
    u"Some passes involved in a failed spending attempt have not definitely been spent and are being returned for future use.",
)

SIGNATURE_CHECK_FAILED = MessageType(
    u"zkapauthorizer:storage-client:signature-check-failed",
    [PASS_COUNT],
    u"Some passes the client tried to use were rejected for having invalid signatures.",
)

CALL_WITH_PASSES = ActionType(
    u"zkapauthorizer:storage-client:call-with-passes",
    [PASS_COUNT],
    [],
    u"A storage operation is being started which may spend some passes.",
)
