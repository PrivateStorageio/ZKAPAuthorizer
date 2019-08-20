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


CONFIG_DB_NAME = u"privatestorageio-zkapauthz-v1.sqlite3"

def open_and_initialize(path, required_schema_version, connect=None):
    """
    Open a SQLite3 database for use as a voucher store.

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

    # Enforcement of foreign key constraints is off by default.  It must be
    # enabled on a per-connection basis.  This is a helpful feature to ensure
    # consistency so we want it enforced and we use it in our schema.
    conn.execute("PRAGMA foreign_keys = ON")

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
            CREATE TABLE IF NOT EXISTS [vouchers] (
                [number] text,
                [redeemed] num DEFAULT 0,

                PRIMARY KEY([number])
            )
            """,
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS [tokens] (
                [text] text, -- The random string that defines the token.
                [voucher] text, -- Reference to the voucher these tokens go with.

                PRIMARY KEY([text])
                FOREIGN KEY([voucher]) REFERENCES [vouchers]([number])
            )
            """,
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS [passes] (
                [text] text, -- The string that defines the pass.

                PRIMARY KEY([text])
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
class VoucherStore(object):
    """
    This class implements persistence for vouchers.

    :ivar allmydata.node._Config node_config: The Tahoe-LAFS node configuration object for
        the node that owns the persisted vouchers.
    """
    database_path = attr.ib(validator=attr.validators.instance_of(FilePath))
    _connection = attr.ib()

    @classmethod
    def from_node_config(cls, node_config, connect=None):
        """
        Create or open the ``VoucherStore`` for a given node.

        :param allmydata.node._Config node_config: The Tahoe-LAFS
            configuration object for the node for which we want to open a
            store.

        :param connect: An alternate database connection function.  This is
            primarily for the purposes of the test suite.
        """
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
    def get(self, cursor, voucher):
        """
        :param unicode voucher: The text value of a voucher to retrieve.

        :return Voucher: The voucher object that matches the given value.
        """
        cursor.execute(
            """
            SELECT
                [number], [redeemed]
            FROM
                [vouchers]
            WHERE
                [number] = ?
            """,
            (voucher,),
        )
        refs = cursor.fetchall()
        if len(refs) == 0:
            raise KeyError(voucher)
        return Voucher(refs[0][0], bool(refs[0][1]))

    @with_cursor
    def add(self, cursor, voucher, tokens):
        """
        Add a new voucher and associated random tokens to the database.  If a
        voucher with the given text value is already present, do nothing.

        :param unicode voucher: The text value of a voucher to add.

        :param list[RandomToken]: The tokens to add alongside the voucher.
        """
        cursor.execute(
            """
            INSERT OR IGNORE INTO [vouchers] ([number]) VALUES (?)
            """,
            (voucher,)
        )
        if cursor.rowcount:
            # Something was inserted.  Insert the tokens, too.  It's okay to
            # drop the tokens in the other case.  They've never been used.
            # What's *already* in the database, on the other hand, may already
            # have been submitted in a redeem attempt and must not change.
            cursor.executemany(
                """
                INSERT INTO [tokens] ([voucher], [text]) VALUES (?, ?)
                """,
                list(
                    (voucher, token.token_value)
                    for token
                    in tokens
                ),
            )

    @with_cursor
    def list(self, cursor):
        """
        Get all known vouchers.

        :return list[Voucher]: All vouchers known to the store.
        """
        cursor.execute(
            """
            SELECT [number], [redeemed] FROM [vouchers]
            """,
        )
        refs = cursor.fetchall()

        return list(
            Voucher(number, bool(redeemed))
            for (number, redeemed)
            in refs
        )

    @with_cursor
    def insert_passes_for_voucher(self, cursor, voucher, passes):
        """
        Store some passes.

        :param unicode voucher: The voucher associated with the passes.  This
            voucher will be marked as redeemed to indicate it has fulfilled
            its purpose and has no further use for us.

        :param list[Pass] passes: The passes to store.
        """
        cursor.executemany(
            """
            INSERT INTO [passes] VALUES (?)
            """,
            list((p.text,) for p in passes),
        )
        cursor.execute(
            """
            UPDATE [vouchers] SET [redeemed] = 1 WHERE [number] = ?
            """,
            (voucher,),
        )

    @with_cursor
    def extract_passes(self, cursor, count):
        """
        Remove and return some passes.

        :param int count: The maximum number of passes to remove and return.
            If fewer passes than this are available, only as many as are
            available are returned.

        :return list[Pass]: The removed passes.
        """
        cursor.execute(
            """
            CREATE TEMPORARY TABLE [extracting-passes]
            AS
            SELECT [text] FROM [passes] LIMIT ?
            """,
            (count,),
        )
        cursor.execute(
            """
            DELETE FROM [passes] WHERE [text] IN [extracting-passes]
            """,
        )
        cursor.execute(
            """
            SELECT [text] FROM [extracting-passes]
            """,
        )
        texts = cursor.fetchall()
        cursor.execute(
            """
            DROP TABLE [extracting-passes]
            """,
        )
        return list(
            Pass(t)
            for (t,)
            in texts
        )


@attr.s(frozen=True)
class Pass(object):
    """
    A ``Pass`` instance completely represents a single Zero-Knowledge Access Pass.

    :ivar unicode text: The text value of the pass.  This can be sent to a
        service provider one time to anonymously prove a prior voucher
        redemption.  If it is sent more than once the service provider may
        choose to reject it and the anonymity property is compromised.  Pass
        text should be kept secret.  If pass text is divulged to third-parties
        the anonymity property may be compromised.
    """
    text = attr.ib(validator=attr.validators.instance_of(unicode))


@attr.s(frozen=True)
class RandomToken(object):
    token_value = attr.ib(validator=attr.validators.instance_of(unicode))


@attr.s
class Voucher(object):
    number = attr.ib()
    redeemed = attr.ib(default=False, validator=attr.validators.instance_of(bool))

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
