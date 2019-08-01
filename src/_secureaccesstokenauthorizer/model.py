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
    connect,
)

import attr

from twisted.python.filepath import (
    FilePath,
)


class StoreAddError(Exception):
    def __init__(self, reason):
        self.reason = reason


class StoreDirectoryError(Exception):
    def __init__(self, reason):
        self.reason = reason


class SchemaError(TypeError):
    pass


CONFIG_DB_NAME = u"privatestorageio-satauthz-v1.sqlite3"

def open_and_initialize(path):
    try:
        path.parent().makedirs(ignoreExistingDirectory=True)
    except OSError as e:
        raise StoreDirectoryError(e)

    conn = connect(
        path.asBytesMode().path,
        isolation_level="IMMEDIATE",
    )
    with conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS [version] AS SELECT 1 AS [version]
            """
        )
        cursor.execute(
            """
            SELECT [version] FROM [version]
            """
        )
        expected = [(1,)]
        version = cursor.fetchall()
        if version != expected:
            raise SchemaError(
                "Unexpected database schema version.  Expected {}.  Got {}.".format(
                    expected,
                    version,
                ),
            )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS [payment-references] (
                number text,

                PRIMARY KEY(number)
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
    def from_node_config(cls, node_config):
        db_path = FilePath(node_config.get_private_path(CONFIG_DB_NAME))
        conn = open_and_initialize(
            db_path,
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
