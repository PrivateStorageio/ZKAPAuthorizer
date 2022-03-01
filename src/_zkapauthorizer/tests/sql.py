"""
Model SQL-related datatypes.

This is focused on SQLite3 and no doubt nevertheless incomplete.  The goal is
to support testing the replication/recovery system.
"""

from enum import Enum, auto
from typing import Any, List, Tuple

from attrs import define


class StorageAffinity(Enum):
    """
    Represent the different "storage affinities" possible for a SQLite3
    column.
    """

    # Notably, this excludes REAL because I don't know how to get floating
    # point values to round-trip through the snapshot/recover implementation
    # on Windows.  ZKAPAuthorizer itself doesn't need REAL / floating point
    # values so this limitation doesn't bother us in practice (ideally
    # something somewhere would enforce this so no one accidentally starts
    # using floating point values thinking the system will handle them).

    INT = auto()
    TEXT = auto()
    BLOB = auto()
    NUMERIC = auto()


@define(frozen=True)
class Column:
    """
    Represent a column in a SQLite3 table.

    :ivar affinity: The expected type affinity for values in this column.  See
        https://www.sqlite.org/datatype3.html
    """

    affinity: StorageAffinity


@define(frozen=True)
class Table:
    """
    Represent a table in a SQLite3 database.

    :ivar columns: The columns that make up this table.
    """

    columns: List[Tuple[str, Column]]


@define(frozen=True)
class Insert:
    """
    Represent an insertion of one row into a table.

    :ivar table_name: The name of the table where the row can be inserted.

    :ivar table: A representation of the table itself.

    :ivar fields: The values which can be inserted.
    """

    table_name: str
    table: Table
    fields: Tuple[Any]

    def statement(self):
        names = ", ".join((escape(name) for (name, _) in self.table.columns))
        placeholders = ", ".join("?" * len(self.table.columns))
        return (
            f"INSERT INTO {escape(self.table_name)} "
            f"({names}) "
            f"VALUES ({placeholders})"
        )

    def arguments(self):
        return self.fields


@define(frozen=True)
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
    fields: Tuple[Any]

    def statement(self):
        field_names = list(name for (name, _) in self.table.columns)
        assignments = ", ".join(f"{escape(name)} = ?" for name in field_names)
        return f"UPDATE {escape(self.table_name)} SET {assignments}"

    def arguments(self):
        return self.fields


@define(frozen=True)
class Delete:
    """
    Represent the deletion of some rows from a table.

    Currently this deletes all rows.

    :ivar table_name: The name of the table from which to rows can be deleted.
    """

    table_name: str

    def statement(self):
        return f"DELETE FROM {escape(self.table_name)}"

    def arguments(self):
        return ()


def escape(string: str) -> str:
    """
    Escape an arbitrary string for use as a SQLite3 identifier.
    """
    return f"[{string}]"


def column_ddl(name: str, column: Column) -> str:
    """
    Get a column DDL fragment for a column of the given name and type.

    :return: *bar* in **create table foo ( bar )**
    """
    return f"{escape(name)} {column.affinity.name}"


def create_table(name: str, table: Table) -> str:
    """
    Get a table creation DDL statement for a table of the given name and type.
    """
    columns = ", ".join(column_ddl(name, column) for (name, column) in table.columns)
    return f"CREATE TABLE {escape(name)} ({columns})"
