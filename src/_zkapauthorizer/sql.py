"""
Model SQL-related datatypes.

This is focused on SQLite3 and no doubt nevertheless incomplete.  The goal is
to support testing the replication/recovery system.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum, auto
from sqlite3 import Connection as _SQLite3Connection
from typing import Any, ContextManager, Iterable, Optional, Protocol, Union

from attrs import frozen
from sqlparse import parse

SQLType = Union[int, float, str, bytes, datetime, None]
SQLRuntimeType = (int, float, str, bytes, datetime, type(None))


class AbstractCursor(Protocol):
    """
    A SQLite3 database cursor.
    """

    @property
    def lastrowid(self) -> Optional[int]:
        ...

    @property
    def rowcount(self) -> Optional[int]:
        ...

    def execute(self, statement: str, args: Iterable[Any]) -> AbstractCursor:
        ...

    def executemany(self, statement, args: Iterable[Iterable[Any]]) -> AbstractCursor:
        ...

    def close(self) -> None:
        ...

    def fetchall(self) -> list[Any]:
        ...

    def fetchmany(self, n: int) -> list[Any]:
        ...

    def fetchone(self) -> Any:
        ...


class AbstractConnection(Protocol):
    """
    A SQLite3 database connection.
    """

    def iterdump(self) -> Iterable[str]:
        ...

    def cursor(self, cursorClass: Optional[type] = None) -> AbstractCursor:
        ...

    def __enter__(self) -> ContextManager:
        ...

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_value: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> bool:
        ...


Connection = AbstractConnection
Cursor = AbstractCursor


class UnboundConnect(Protocol):
    """
    Connect to a SQLite3 database.
    """

    def __call__(
        self,
        path: str,
        timeout: int = None,
        detect_types: bool = None,
        isolation_level: str = None,
        check_same_thread: bool = False,
        factory: Any = None,
        cached_statements: Any = None,
    ) -> _SQLite3Connection:
        """
        Get a new database connection.
        """


class BoundConnect(Protocol):
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
    ) -> _SQLite3Connection:
        """
        Get a new database connection.
        """


class StorageAffinity(Enum):
    """
    Represent the different "storage affinities" possible for a SQLite3
    column.
    """

    INT = auto()
    TEXT = auto()
    BLOB = auto()
    REAL = auto()
    NUMERIC = auto()


@frozen
class Column:
    """
    Represent a column in a SQLite3 table.

    :ivar affinity: The expected type affinity for values in this column.  See
        https://www.sqlite.org/datatype3.html
    """

    affinity: StorageAffinity


@frozen
class Table:
    """
    Represent a table in a SQLite3 database.

    :ivar columns: The columns that make up this table.
    """

    columns: list[tuple[str, Column]]


@frozen
class Insert:
    """
    Represent an insertion of one row into a table.

    :ivar table_name: The name of the table where the row can be inserted.

    :ivar table: A representation of the table itself.

    :ivar fields: The values which can be inserted.
    """

    table_name: str
    table: Table
    fields: tuple[SQLType, ...]

    def statement(self):
        names = ", ".join((escape_identifier(name) for (name, _) in self.table.columns))
        placeholders = ", ".join("?" * len(self.table.columns))
        return (
            f"INSERT INTO {escape_identifier(self.table_name)} "
            f"({names}) "
            f"VALUES ({placeholders})"
        )

    def arguments(self) -> tuple[SQLType, ...]:
        return self.fields


def quote_sql_value(cursor: Cursor, value: SQLType) -> str:
    """
    Use the SQL `quote()` function to return the quoted version of `value`.

    :returns: the quoted value
    """
    if isinstance(value, (int, float, datetime)):
        return str(value)
    if value is None:
        return "NULL"
    if isinstance(value, (str, bytes)):
        cursor.execute("SELECT quote(?);", (value,))
        result = cursor.fetchall()[0][0]
        assert isinstance(result, str)
        return result
    raise ValueError(f"Do not know how to quote value of type {type(value)}")


@frozen
class Update:
    """
    Represent an update to some rows in a table.

    Currently this updates all rows.

    :ivar table_name: The name of the table to which the update applies.

    :ivar table: A representation of the table itself.

    :ivar fields: The new values for each column in the table.
    """

    table_name: str
    table: Table
    fields: tuple[SQLType, ...]

    def statement(self):
        field_names = list(name for (name, _) in self.table.columns)
        assignments = ", ".join(
            f"{escape_identifier(name)} = ?" for name in field_names
        )
        return f"UPDATE {escape_identifier(self.table_name)} SET {assignments}"

    def arguments(self) -> tuple[SQLType, ...]:
        return self.fields


@frozen
class Select:
    """
    Represent a query about a certain table

    :ivar table_name: valid SQL identifier for a table
    """

    table_name: str

    def statement(self):
        return f"SELECT * FROM {escape_identifier(self.table_name)}"

    def arguments(self) -> tuple[()]:
        return ()


@frozen
class Delete:
    """
    Represent the deletion of some rows from a table.

    Currently this deletes all rows.

    :ivar table_name: The name of the table from which to rows can be deleted.
    """

    table_name: str

    def statement(self):
        return f"DELETE FROM {escape_identifier(self.table_name)}"

    def arguments(self) -> tuple[()]:
        return ()


def escape_identifier(string: str) -> str:
    """
    Escape an arbitrary string for use as a SQLite3 identifier.
    """
    return f"'{string}'"


def column_ddl(name: str, column: Column) -> str:
    """
    Get a column DDL fragment for a column of the given name and type.

    :return: *bar* in **create table foo ( bar )**
    """
    return f"{escape_identifier(name)} {column.affinity.name}"


def create_table(name: str, table: Table) -> str:
    """
    Get a table creation DDL statement for a table of the given name and type.
    """
    columns = ", ".join(column_ddl(name, column) for (name, column) in table.columns)
    return f"CREATE TABLE {escape_identifier(name)} ({columns})"


def statement_mutates(statement: str) -> bool:
    """
    predicate to decide if `statement` will change the database
    """
    if statement == "BEGIN IMMEDIATE TRANSACTION":
        return False
    (parsed,) = parse(statement)
    return parsed.get_type() not in {"SELECT"}
