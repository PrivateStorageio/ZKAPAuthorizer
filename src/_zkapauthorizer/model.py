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
from datetime import (
    datetime,
)
from sqlite3 import (
    OperationalError,
    connect as _connect,
)

import attr

from aniso8601 import (
    parse_datetime,
)
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
            # A denormalized schema because, for now, it's simpler. :/
            """
            CREATE TABLE IF NOT EXISTS [vouchers] (
                [number] text,
                [created] text,                     -- An ISO8601 date+time string.
                [state] text DEFAULT "pending",     -- pending, double-spend, redeemed

                [finished] text DEFAULT NULL,       -- ISO8601 date+time string when
                                                    -- the current terminal state was entered.

                [token-count] num DEFAULT NULL,     -- Set in the redeemed state to the number
                                                    -- of tokens received on this voucher's
                                                    -- redemption.

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
            CREATE TABLE IF NOT EXISTS [unblinded-tokens] (
                [token] text, -- The base64 encoded unblinded token.

                PRIMARY KEY([token])
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

    :ivar now: A no-argument callable that returns the time of the call as a
        ``datetime`` instance.
    """
    database_path = attr.ib(validator=attr.validators.instance_of(FilePath))
    now = attr.ib()

    _connection = attr.ib()

    @classmethod
    def from_node_config(cls, node_config, now, connect=None):
        """
        Create or open the ``VoucherStore`` for a given node.

        :param allmydata.node._Config node_config: The Tahoe-LAFS
            configuration object for the node for which we want to open a
            store.

        :param now: See ``VoucherStore.now``.

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
            now,
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
                [number], [created], [state], [finished], [token-count]
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
        return Voucher.from_row(refs[0])

    @with_cursor
    def add(self, cursor, voucher, tokens):
        """
        Add a new voucher and associated random tokens to the database.  If a
        voucher with the given text value is already present, do nothing.

        :param unicode voucher: The text value of a voucher to add.

        :param list[RandomToken]: The tokens to add alongside the voucher.
        """
        now = self.now()
        if not isinstance(now, datetime):
            raise TypeError("{} returned {}, expected datetime".format(self.now, now))

        cursor.execute(
            """
            INSERT OR IGNORE INTO [vouchers] ([number], [created]) VALUES (?, ?)
            """,
            (voucher, self.now())
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
            SELECT
                [number], [created], [state], [finished], [token-count]
            FROM
                [vouchers]
            """,
        )
        refs = cursor.fetchall()

        return list(
            Voucher.from_row(row)
            for row
            in refs
        )

    @with_cursor
    def insert_unblinded_tokens_for_voucher(self, cursor, voucher, unblinded_tokens):
        """
        Store some unblinded tokens.

        :param unicode voucher: The voucher associated with the unblinded
            tokens.  This voucher will be marked as redeemed to indicate it
            has fulfilled its purpose and has no further use for us.

        :param list[UnblindedToken] unblinded_tokens: The unblinded tokens to
            store.
        """
        cursor.executemany(
            """
            INSERT INTO [unblinded-tokens] VALUES (?)
            """,
            list(
                (t.text,)
                for t
                in unblinded_tokens
            ),
        )
        cursor.execute(
            """
            UPDATE [vouchers]
            SET [state] = "redeemed"
              , [token-count] = ?
              , [finished] = ?
            WHERE [number] = ?
            """,
            (len(unblinded_tokens), self.now(), voucher),
        )

    @with_cursor
    def mark_voucher_double_spent(self, cursor, voucher):
        """
        Mark a voucher as having failed redemption because it has already been
        spent.
        """
        cursor.execute(
            """
            UPDATE [vouchers]
            SET [state] = "double-spend"
              , [finished] = ?
            WHERE [number] = ?
              AND [state] = "pending"
            """,
            (self.now(), voucher),
        )
        if cursor.rowcount == 0:
            # Was there no matching voucher or was it in the wrong state?
            cursor.execute(
                """
                SELECT [state]
                FROM [vouchers]
                WHERE [number] = ?
                """,
                (voucher,)
            )
            rows = cursor.fetchall()
            if len(rows) == 0:
                raise ValueError("Voucher {} not found".format(voucher))
            else:
                raise ValueError(
                    "Voucher {} in state {} cannot transition to double-spend".format(
                        voucher,
                        rows[0][0],
                    ),
                )


    @with_cursor
    def extract_unblinded_tokens(self, cursor, count):
        """
        Remove and return some unblinded tokens.

        :param int count: The maximum number of unblinded tokens to remove and
            return.  If fewer than this are available, only as many as are
            available are returned.

        :return list[UnblindedTokens]: The removed unblinded tokens.
        """
        cursor.execute(
            """
            CREATE TEMPORARY TABLE [extracting]
            AS
            SELECT [token] FROM [unblinded-tokens] ORDER BY [token] LIMIT ?
            """,
            (count,),
        )
        cursor.execute(
            """
            DELETE FROM [unblinded-tokens] WHERE [token] IN [extracting]
            """,
        )
        cursor.execute(
            """
            SELECT [token] FROM [extracting]
            """,
        )
        texts = cursor.fetchall()
        cursor.execute(
            """
            DROP TABLE [extracting]
            """,
        )
        return list(
            UnblindedToken(t)
            for (t,)
            in texts
        )

    @with_cursor
    def backup(self, cursor):
        """
        Read out all state necessary to recreate this database in the event it is
        lost.
        """
        cursor.execute(
            """
            SELECT [token] FROM [unblinded-tokens] ORDER BY [token]
            """,
        )
        tokens = cursor.fetchall()
        return {
            u"unblinded-tokens": list(token for (token,) in tokens),
        }


@attr.s(frozen=True)
class UnblindedToken(object):
    """
    An ``UnblindedToken`` instance represents cryptographic proof of a voucher
    redemption.  It is an intermediate artifact in the PrivacyPass protocol
    and can be used to construct a privacy-preserving pass which can be
    exchanged for service.

    :ivar unicode text: The base64 encoded serialized form of the unblinded
        token.  This can be used to reconstruct a
        ``privacypass.UnblindedToken`` using that class's ``decode_base64``
        method.
    """
    text = attr.ib(validator=attr.validators.instance_of(unicode))


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


@attr.s(frozen=True)
class Pending(object):
    def to_json_v1(self):
        return {
            u"name": u"pending",
        }


@attr.s(frozen=True)
class Redeeming(object):
    """
    This is a non-persistent state in which a voucher exists when the database
    state is **pending** but for which there is a redemption operation in
    progress.
    """
    started = attr.ib(validator=attr.validators.instance_of(datetime))

    def to_json_v1(self):
        return {
            u"name": u"redeeming",
            u"started": self.started.isoformat(),
        }


@attr.s(frozen=True)
class Redeemed(object):
    finished = attr.ib(validator=attr.validators.instance_of(datetime))
    token_count = attr.ib(validator=attr.validators.instance_of((int, long)))

    def to_json_v1(self):
        return {
            u"name": u"redeemed",
            u"finished": self.finished.isoformat(),
            u"token-count": self.token_count,
        }


@attr.s(frozen=True)
class DoubleSpend(object):
    finished = attr.ib(validator=attr.validators.instance_of(datetime))

    def to_json_v1(self):
        return {
            u"name": u"double-spend",
            u"finished": self.finished.isoformat(),
        }


@attr.s(frozen=True)
class Unpaid(object):
    """
    This is a non-persistent state in which a voucher exists when the database
    state is **pending** but the most recent redemption attempt has failed due
    to lack of payment.
    """
    finished = attr.ib(validator=attr.validators.instance_of(datetime))

    def to_json_v1(self):
        return {
            u"name": u"unpaid",
            u"finished": self.finished.isoformat(),
        }


@attr.s
class Voucher(object):
    """
    :ivar unicode number: The text string which gives this voucher its
        identity.

    :ivar datetime created: The time at which this voucher was added to this
        node.

    :ivar bool redeemed: ``True`` if this voucher has successfully been
        redeemed with a payment server, ``False`` otherwise.

    :ivar int token_count: A number of tokens received from the redemption of
        this voucher if it has been redeemed, ``None`` if it has not been
        redeemed.
    """
    number = attr.ib()
    created = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(datetime)),
    )
    state = attr.ib(default=Pending())

    @classmethod
    def from_row(cls, row):
        def state_from_row(state, row):
            if state == u"pending":
                return Pending()
            if state == u"double-spend":
                return DoubleSpend(
                    parse_datetime(row[0], delimiter=u" "),
                )
            if state == u"redeemed":
                return Redeemed(
                    parse_datetime(row[0], delimiter=u" "),
                    row[1],
                )
            raise ValueError("Unknown voucher state {}".format(state))

        number, created, state = row[:3]
        return cls(
            number,
            # All Python datetime-based date/time libraries fail to handle
            # leap seconds.  This parse call might raise an exception of the
            # value represents a leap second.  However, since we also use
            # Python to generate the data in the first place, it should never
            # represent a leap second... I hope.
            parse_datetime(created, delimiter=u" "),
            state_from_row(state, row[3:])
        )

    @classmethod
    def from_json(cls, json):
        values = loads(json)
        version = values.pop(u"version")
        return getattr(cls, "from_json_v{}".format(version))(values)


    @classmethod
    def from_json_v1(cls, values):
        state_json = values[u"state"]
        state_name = state_json[u"name"]
        if state_name == u"pending":
            state = Pending()
        elif state_name == u"redeeming":
            state = Redeeming(
                started=parse_datetime(state_json[u"started"]),
            )
        elif state_name == u"double-spend":
            state = DoubleSpend(
                finished=parse_datetime(state_json[u"finished"]),
            )
        elif state_name == u"redeemed":
            state = Redeemed(
                finished=parse_datetime(state_json[u"finished"]),
                token_count=state_json[u"token-count"],
            )
        elif state_name == u"unpaid":
            state = Unpaid(
                finished=parse_datetime(state_json[u"finished"]),
            )
        else:
            raise ValueError("Unrecognized state {!r}".format(state_json))

        return cls(
            number=values[u"number"],
            created=None if values[u"created"] is None else parse_datetime(values[u"created"]),
            state=state,
        )


    def to_json(self):
        return dumps(self.marshal())


    def marshal(self):
        return self.to_json_v1()


    def to_json_v1(self):
        state = self.state.to_json_v1()
        return {
            u"number": self.number,
            u"created": None if self.created is None else self.created.isoformat(),
            u"state": state,
            u"version": 1,
        }
