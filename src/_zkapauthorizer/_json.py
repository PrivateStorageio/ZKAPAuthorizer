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

from json import dumps as _dumps
from json import loads as _loads
from typing import Any, cast

from ._types import JSON


def dumps_utf8(o: Any) -> bytes:
    """
    Serialize an object to a UTF-8-encoded JSON byte string.
    """
    return _dumps(o).encode("utf-8")


def loads(data: bytes) -> JSON:
    """
    Load a JSON object from a byte string.

    Raise an exception including ``data`` if the parse fails.
    """
    try:
        return cast(JSON, _loads(data))
    except ValueError as e:
        raise ValueError("{!r}: {!r}".format(e, data))
