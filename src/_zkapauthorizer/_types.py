from sqlite3 import Connection
from typing import Any, Callable, Protocol

GetTime = Callable[[], float]


class Connect(Protocol):
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
