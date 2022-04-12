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

from sqlite3 import Connection
from typing import Any, Callable, Protocol

GetTime = Callable[[], float]


class Connect(Protocol):
    """
    Connect to a certain (ie, not parameterized) SQLite3 database.
    """

    def __call__(
        self,
        timeout: int = None,
        detect_types: bool = None,
        isolation_level: str = None,
        check_same_thread: bool = False,
        factory: Any = None,
        cached_statements: Any = None,
    ) -> Connection:
        """
        Get a new database connection.
        """
