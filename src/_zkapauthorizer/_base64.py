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
This module implements base64 encoding-related functionality.
"""

from base64 import b64decode as _b64decode
from binascii import Error
from re import compile as _compile

_b64decode_validator = _compile(b"^[A-Za-z0-9-_]*={0,2}$")


def urlsafe_b64decode(s):
    """
    Like ``base64.b64decode`` but with validation.
    """
    if not _b64decode_validator.match(s):
        raise Error("Non-base64 digit found")
    return _b64decode(s, altchars=b"-_")
