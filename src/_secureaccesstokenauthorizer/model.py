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
This module implements models (in the MVC sense) for the client side of
the storage plugin.
"""

from functools import (
    wraps,
)
from json import (
    loads,
    dumps,
)

from sqlite3 import (
    OperationalError,
    connect as _connect,
)

import attr

from twisted.python.filepath import (
    FilePath,
)


class StoreOpenError(Exception):
    """
    There was a problem opening the underlying data store.
    """
    def __init__(self, reason):
        self.reason = reason


class SchemaError(TypeError):
    pass


CONFIG_DB_NAME = u"privatestorageio-satauthz-v1.sqlite3"

def open_and_initialize(path, required_schema_version, connect=None):
    """
    Open a SQLite3 database for use as a payment reference store.

    Create the database and populate it with a schema, if it does not already
    exist.

    :param FilePath path: The location of the SQLite3 database file.

    :param int required_schema_version: The schema version which must be
        present in the database in order for a SQLite3 connection to be
        returned.

    :raise SchemaError: If the schema in the database does not match the
        required schema version.

    :return: A SQLite3 connection object for the database at the given path.
    """
    if connect is None:
        connect = _connect
    try:
        path.parent().makedirs(ignoreExistingDirectory=True)
    except OSError as e:
        raise StoreOpenError(e)

    dbfile = path.asBytesMode().path
    try:
        conn = connect(
            dbfile,
            isolation_level="IMMEDIATE",
        )
    except OperationalError as e:
        raise StoreOpenError(e)

    with conn:
        cursor = conn.cursor()
        cursor.execute(
            # This code knows how to create schema version 1.  This is
            # regardless of what the caller *wants* to find in the database.
            """
            CREATE TABLE IF NOT EXISTS [version] AS SELECT 1 AS [version]
            """
        )
        cursor.execute(
            """
            SELECT [version] FROM [version]
            """
        )
        [(actual_version,)] = cursor.fetchall()
        if actual_version != required_schema_version:
            raise SchemaError(
                "Unexpected database schema version.  Required {}.  Got {}.".format(
                    required_schema_version,
                    actual_version,
                ),
            )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS [payment-references] (
                [number] text,

                PRIMARY KEY([number])
            )
            """,
        )
    return conn


def with_cursor(f):
    @wraps(f)
    def with_cursor(self, *a, **kw):
        with self._connection:
            return f(self, self._connection.cursor(), *a, **kw)
    return with_cursor


def memory_connect(path, *a, **kw):
    """
    Always connect to an in-memory SQLite3 database.
    """
    return _connect(":memory:", *a, **kw)


@attr.s(frozen=True)
class PaymentReferenceStore(object):
    """
    This class implements persistence for payment references.

    :ivar allmydata.node._Config node_config: The Tahoe-LAFS node configuration object for
        the node that owns the persisted payment preferences.
    """
    database_path = attr.ib(type=FilePath)
    _connection = attr.ib()

    @classmethod
    def from_node_config(cls, node_config, connect=None):
        db_path = FilePath(node_config.get_private_path(CONFIG_DB_NAME))
        conn = open_and_initialize(
            db_path,
            required_schema_version=1,
            connect=connect,
        )
        return cls(
            db_path,
            conn,
        )

    @with_cursor
    def get(self, cursor, prn):
        cursor.execute(
            """
            SELECT
                ([number])
            FROM
                [payment-references]
            WHERE
                [number] = ?
            """,
            (prn,),
        )
        refs = cursor.fetchall()
        if len(refs) == 0:
            raise KeyError(prn)
        return PaymentReference(refs[0][0])

    @with_cursor
    def add(self, cursor, prn):
        cursor.execute(
            """
            INSERT OR IGNORE INTO [payment-references] VALUES (?)
            """,
            (prn,)
        )

    @with_cursor
    def list(self, cursor):
        cursor.execute(
            """
            SELECT ([number]) FROM [payment-references]
            """,
        )
        refs = cursor.fetchall()

        return list(
            PaymentReference(number)
            for (number,)
            in refs
        )


@attr.s
class PaymentReference(object):
    number = attr.ib()

    @classmethod
    def from_json(cls, json):
        values = loads(json)
        version = values.pop(u"version")
        return getattr(cls, "from_json_v{}".format(version))(values)


    @classmethod
    def from_json_v1(cls, values):
        return cls(**values)


    def to_json(self):
        return dumps(self.marshal())


    def marshal(self):
        return self.to_json_v1()


    def to_json_v1(self):
        result = attr.asdict(self)
        result[u"version"] = 1
        return result
