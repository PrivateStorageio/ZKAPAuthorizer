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
from typing import Callable
from attrs import Attribute as _Attribute
from typing import TYPE_CHECKING, Generic, TypeVar

# A Tahoe-LAFS capability string
CapStr = str

GetTime = Callable[[], datetime]

_T = TypeVar("_T")

if TYPE_CHECKING:
    Attribute = _Attribute
else:
    class Attribute(_Attribute, Generic[_T]):
        pass
