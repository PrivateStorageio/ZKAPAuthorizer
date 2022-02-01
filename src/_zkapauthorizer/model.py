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

from datetime import datetime
from functools import wraps
from json import loads
from sqlite3 import OperationalError
from sqlite3 import connect as _connect

import attr
from aniso8601 import parse_datetime
from twisted.logger import Logger
from twisted.python.filepath import FilePath
from zope.interface import Interface, implementer

from ._base64 import urlsafe_b64decode
from ._json import dumps_utf8
from .schema import get_schema_upgrades, get_schema_version, run_schema_upgrades
from .storage_common import (
    get_configured_pass_value,
    pass_value_attribute,
    required_passes,
)
from .validators import greater_than, has_length, is_base64_encoded


class ILeaseMaintenanceObserver(Interface):
    """
    An object which is interested in receiving events related to the progress
    of lease maintenance activity.
    """

    def observe(sizes):
        """
        Observe some shares encountered during lease maintenance.

        :param list[int] sizes: The sizes of the shares encountered.
        """

    def finish():
        """
        Observe that a run of lease maintenance has completed.
        """


class StoreOpenError(Exception):
    """
    There was a problem opening the underlying data store.
    """

    def __init__(self, reason):
        self.reason = reason


class NotEnoughTokens(Exception):
    """
    An attempt to extract tokens failed because the store does not contain as
    many tokens as were requested.
    """


# The version number in _zkapauthorizer.api.NAME doesn't match the version
# here because the database is persistent state and we need to be sure to load
# the older version even if we signal an API compatibility break by bumping
# the version number elsewhere.  Consider this version number part of a
# different scheme where we're versioning our ability to open the database at
# all.  The schema inside the database is versioned by yet another mechanism.
CONFIG_DB_NAME = "privatestorageio-zkapauthz-v1.sqlite3"


def open_and_initialize(path, connect=None):
    """
    Open a SQLite3 database for use as a voucher store.

    Create the database and populate it with a schema, if it does not already
    exist.

    :param FilePath path: The location of the SQLite3 database file.

    :return: A SQLite3 connection object for the database at the given path.
    """
    if connect is None:
        connect = _connect
    try:
        path.parent().makedirs(ignoreExistingDirectory=True)
    except OSError as e:
        raise StoreOpenError(e)

    try:
        conn = connect(
            path.path,
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
        actual_version = get_schema_version(cursor)
        schema_upgrades = list(get_schema_upgrades(actual_version))
        run_schema_upgrades(schema_upgrades, cursor)

    # Create some tables that only exist (along with their contents) for
    # this connection.  These are outside of the schema because they are not
    # persistent.  We can change them any time we like without worrying about
    # upgrade logic because we re-create them on every connection.
    conn.execute(
        """
        -- Track tokens in use by the process holding this connection.
        CREATE TEMPORARY TABLE [in-use] (
            [unblinded-token] text, -- The base64 encoded unblinded token.

            PRIMARY KEY([unblinded-token])
            -- A foreign key on unblinded-token to [unblinded-tokens]([token])
            -- would be alright - however SQLite3 foreign key constraints
            -- can't cross databases (and temporary tables are considered to
            -- be in a different database than normal tables).
        )
        """,
    )
    conn.execute(
        """
        -- Track tokens that we want to remove from the database.  Mainly just
        -- works around the awkward DB-API interface for dealing with deleting
        -- many rows.
        CREATE TEMPORARY TABLE [to-discard] (
            [unblinded-token] text
        )
        """,
    )
    conn.execute(
        """
        -- Track tokens that we want to remove from the [in-use] set.  Similar
        -- to [to-discard].
        CREATE TEMPORARY TABLE [to-reset] (
            [unblinded-token] text
        )
        """,
    )
    return conn


def with_cursor(f):
    """
    Decorate a function so it is automatically passed a cursor with an active
    transaction as the first positional argument.  If the function returns
    normally then the transaction will be committed.  Otherwise, the
    transaction will be rolled back.
    """

    @wraps(f)
    def with_cursor(self, *a, **kw):
        with self._connection:
            cursor = self._connection.cursor()
            cursor.execute("BEGIN IMMEDIATE TRANSACTION")
            statements = []
            result = f(self, add_application_logging(cursor, statements), *a, **kw)
            write_recorded_statements(cursor, statements)
            return result

    return with_cursor

def sqlquote(value):
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, None):
        return "NULL"
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"

def write_recorded_statements(cursor, statements):
    for (sql, args) in statements:
        # sql="INSERT INTO foo VALUES (?, ?)" args=(1, 2)
        # sql="INSERT INTO foo VALUES (1, 2)" args=()
        dump_compat_string = sql.replace("?", "{}").format(*(
            sqlquote(arg)
            for arg
            in args
        ))
        cursor.execute("INSERT INTO [event-stream] (?)", (dump_compat_string,))

# TODO
#   filter out reads
#   build the recovery system
#     * download the database snapshot
#     * download the event-stream
#     * apply the event stream starting from the right place
#   implement local [event-stream] pruning so database doesn't grow without bounds
#   add sequence numbers or something so you know where you are in [event-stream] for certain operations
#   schedule [event-stream] uploads
#   add automated tests
#   as an optimization:
#     implement initial database snapshot and updates to that
#     * take a write lock
#     * .dump the database w/o the [event-stream] table
#     * upload the copy to the grid
#     * repeat as desired (eg when size of event stream >> size of database snapshot)

# Can we be `.dump` compatible?
#  - Python API to format a SQL string and args as just a SQL string
#    -
#  - Python API to dump the database?
#    - conn.iterdump()

def add_application_logging(cursor, statements):
    class _Cursor(object):
        def executemany(self, sql, args):
            statements.append((sql, args))
            return cursor.executemany(sql, args)
    return _Cursor()


def memory_connect(path, *a, **kw):
    """
    Always connect to an in-memory SQLite3 database.
    """
    return _connect(":memory:", *a, **kw)


# The largest integer SQLite3 can represent in an integer column.  Larger than
# this an the representation loses precision as a floating point.
_SQLITE3_INTEGER_MAX = 2 ** 63 - 1


@attr.s(frozen=True)
class VoucherStore(object):
    """
    This class implements persistence for vouchers.

    :ivar allmydata.node._Config node_config: The Tahoe-LAFS node configuration object for
        the node that owns the persisted vouchers.

    :ivar now: A no-argument callable that returns the time of the call as a
        ``datetime`` instance.
    """

    _log = Logger()

    pass_value = pass_value_attribute()

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
            connect=connect,
        )
        return cls(
            get_configured_pass_value(node_config),
            db_path,
            now,
            conn,
        )

    @with_cursor
    def get(self, cursor, voucher):
        """
        :param bytes voucher: The text value of a voucher to retrieve.

        :return Voucher: The voucher object that matches the given value.
        """
        cursor.execute(
            """
            SELECT
                [number], [created], [expected-tokens], [state], [finished], [token-count], [public-key], [counter]
            FROM
                [vouchers]
            WHERE
                [number] = ?
            """,
            (voucher.decode("ascii"),),
        )
        refs = cursor.fetchall()
        if len(refs) == 0:
            raise KeyError(voucher)
        return Voucher.from_row(refs[0])

    @with_cursor
    def add(self, cursor, voucher, expected_tokens, counter, get_tokens):
        """
        Add random tokens associated with a voucher (possibly new, possibly
        existing) to the database.  If the (voucher, counter) pair is already
        present, do nothing.

        :param bytes voucher: The text value of a voucher with which to
            associate the tokens.

        :param int expected_tokens: The total number of tokens for which this
            voucher is expected to be redeemed.  This is only respected the
            first time a voucher is added.  Subsequent calls with the same
            voucher but a different count ignore the value because it is
            already known (and the database knows better than the caller what
            it should be).

            This probably means ``add`` is a broken interface for doing these
            two things.  Maybe it should be fixed someday.

        :param int counter: The redemption counter for the given voucher with
            which to associate the tokens.

        :param list[RandomToken]: The tokens to add alongside the voucher.
        """
        now = self.now()
        if not isinstance(now, datetime):
            raise TypeError("{} returned {}, expected datetime".format(self.now, now))

        cursor.execute(
            """
            SELECT [text]
            FROM [tokens]
            WHERE [voucher] = ? AND [counter] = ?
            """,
            (voucher.decode("ascii"), counter),
        )
        rows = cursor.fetchall()
        if len(rows) > 0:
            self._log.info(
                "Loaded {count} random tokens for a voucher ({voucher}[{counter}]).",
                count=len(rows),
                voucher=voucher,
                counter=counter,
            )
            tokens = list(
                RandomToken(token_value.encode("ascii")) for (token_value,) in rows
            )
        else:
            tokens = get_tokens()
            self._log.info(
                "Persisting {count} random tokens for a voucher ({voucher}[{counter}]).",
                count=len(tokens),
                voucher=voucher.decode("ascii"),
                counter=counter,
            )
            cursor.execute(
                """
                INSERT OR IGNORE INTO [vouchers] ([number], [expected-tokens], [created]) VALUES (?, ?, ?)
                """,
                (voucher.decode("ascii"), expected_tokens, self.now()),
            )
            cursor.executemany(
                """
                INSERT INTO [tokens] ([voucher], [counter], [text]) VALUES (?, ?, ?)
                """,
                list(
                    (
                        voucher.decode("ascii"),
                        counter,
                        token.token_value.decode("ascii"),
                    )
                    for token in tokens
                ),
            )
        return tokens

    @with_cursor
    def list(self, cursor):
        """
        Get all known vouchers.

        :return list[Voucher]: All vouchers known to the store.
        """
        cursor.execute(
            """
            SELECT
                [number], [created], [expected-tokens], [state], [finished], [token-count], [public-key], [counter]
            FROM
                [vouchers]
            """,
        )
        refs = cursor.fetchall()

        return list(Voucher.from_row(row) for row in refs)

    @with_cursor
    def insert_unblinded_tokens_for_voucher(
        self, cursor, voucher, public_key, unblinded_tokens, completed, spendable
    ):
        """
        Store some unblinded tokens received from redemption of a voucher.

        :param bytes voucher: The voucher associated with the unblinded
            tokens.  This voucher will be marked as redeemed to indicate it
            has fulfilled its purpose and has no further use for us.

        :param str public_key: The encoded public key for the private key
            which was used to sign these tokens.

        :param list[UnblindedToken] unblinded_tokens: The unblinded tokens to
            store.

        :param bool completed: ``True`` if redemption of this voucher is now
            complete, ``False`` otherwise.

        :param bool spendable: ``True`` if it should be possible to spend the
            inserted tokens, ``False`` otherwise.
        """
        if completed:
            voucher_state = "redeemed"
        else:
            voucher_state = "pending"

        if spendable:
            token_count_increase = len(unblinded_tokens)
            sequestered_count_increase = 0
        else:
            token_count_increase = 0
            sequestered_count_increase = len(unblinded_tokens)

        cursor.execute(
            """
            INSERT INTO [redemption-groups] ([voucher], [public-key], [spendable]) VALUES (?, ?, ?)
            """,
            (voucher.decode("ascii"), public_key, spendable),
        )
        group_id = cursor.lastrowid

        self._log.info(
            "Recording {count} {unspendable}spendable unblinded tokens from public key {public_key}.",
            count=len(unblinded_tokens),
            unspendable="" if spendable else "un",
            public_key=public_key,
        )

        cursor.execute(
            """
            UPDATE [vouchers]
            SET [state] = ?
              , [token-count] = COALESCE([token-count], 0) + ?
              , [sequestered-count] = COALESCE([sequestered-count], 0) + ?
              , [finished] = ?
              , [counter] = [counter] + 1
            WHERE [number] = ?
            """,
            (
                voucher_state,
                token_count_increase,
                sequestered_count_increase,
                self.now(),
                voucher.decode("ascii"),
            ),
        )
        if cursor.rowcount == 0:
            raise ValueError(
                "Cannot insert tokens for unknown voucher; add voucher first"
            )

        cursor.executemany(
            """
            INSERT INTO [unblinded-tokens] ([token], [redemption-group]) VALUES (?, ?)
            """,
            list(
                (token.unblinded_token.decode("ascii"), group_id)
                for token in unblinded_tokens
            ),
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
            (self.now(), voucher.decode("ascii")),
        )
        if cursor.rowcount == 0:
            # Was there no matching voucher or was it in the wrong state?
            cursor.execute(
                """
                SELECT [state]
                FROM [vouchers]
                WHERE [number] = ?
                """,
                (voucher.decode("ascii"),),
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
    def get_unblinded_tokens(self, cursor, count):
        """
        Get some unblinded tokens.

        These tokens are not removed from the store but they will not be
        returned from a future call to ``get_unblinded_tokens`` *on this
        ``VoucherStore`` instance* unless ``reset_unblinded_tokens`` is used
        to reset their state.

        If the underlying storage is access via another ``VoucherStore``
        instance then the behavior of this method will be as if all tokens
        which have not had their state changed to invalid or spent have been
        reset.

        :raise NotEnoughTokens: If there are fewer than the requested number
            of tokens available to be spent.  In this case, all tokens remain
            available to future calls and do not need to be reset.

        :return list[UnblindedTokens]: The removed unblinded tokens.
        """
        if count > _SQLITE3_INTEGER_MAX:
            # An unreasonable number of tokens and also large enough to
            # provoke undesirable behavior from the database.
            raise NotEnoughTokens()

        cursor.execute(
            """
            SELECT T.[token]
            FROM   [unblinded-tokens] AS T, [redemption-groups] AS G
            WHERE  T.[redemption-group] = G.[rowid]
            AND    G.[spendable] = 1
            AND    T.[token] NOT IN [in-use]
            LIMIT ?
            """,
            (count,),
        )
        texts = cursor.fetchall()
        if len(texts) < count:
            raise NotEnoughTokens()

        cursor.executemany(
            """
            INSERT INTO [in-use] VALUES (?)
            """,
            texts,
        )
        return list(UnblindedToken(t.encode("ascii")) for (t,) in texts)

    @with_cursor
    def count_unblinded_tokens(self, cursor):
        """
        Return the largest number of unblinded tokens that can be requested from
        ``get_unblinded_tokens`` without causing it to raise
        ``NotEnoughTokens``.
        """
        cursor.execute(
            """
            SELECT count(1)
            FROM   [unblinded-tokens] AS T, [redemption-groups] AS G
            WHERE  T.[redemption-group] = G.[rowid]
            AND    G.[spendable] = 1
            AND    T.[token] NOT IN [in-use]
            """,
        )
        (count,) = cursor.fetchone()
        return count

    @with_cursor
    def discard_unblinded_tokens(self, cursor, unblinded_tokens):
        """
        Get rid of some unblinded tokens.  The tokens will be completely removed
        from the system.  This is useful when the tokens have been
        successfully spent.

        :param list[UnblindedToken] unblinded_tokens: The tokens to discard.

        :return: ``None``
        """
        cursor.executemany(
            """
            INSERT INTO [to-discard] VALUES (?)
            """,
            list(
                (token.unblinded_token.decode("ascii"),) for token in unblinded_tokens
            ),
        )
        cursor.execute(
            """
            DELETE FROM [in-use]
            WHERE [unblinded-token] IN [to-discard]
            """,
        )
        cursor.execute(
            """
            DELETE FROM [unblinded-tokens]
            WHERE [token] IN [to-discard]
            """,
        )
        cursor.execute(
            """
            DELETE FROM [to-discard]
            """,
        )

    @with_cursor
    def invalidate_unblinded_tokens(self, cursor, reason, unblinded_tokens):
        """
        Mark some unblinded tokens as invalid and unusable.  Some record of the
        tokens may be retained for future inspection.  These tokens will not
        be returned by any future ``get_unblinded_tokens`` call.  This is
        useful when an attempt to spend a token has met with rejection by the
        validator.

        :param list[UnblindedToken] unblinded_tokens: The tokens to mark.

        :return: ``None``
        """
        cursor.executemany(
            """
            INSERT INTO [invalid-unblinded-tokens] VALUES (?, ?)
            """,
            list(
                (token.unblinded_token.decode("ascii"), reason)
                for token in unblinded_tokens
            ),
        )
        cursor.execute(
            """
            DELETE FROM [in-use]
            WHERE [unblinded-token] IN (SELECT [token] FROM [invalid-unblinded-tokens])
            """,
        )
        cursor.execute(
            """
            DELETE FROM [unblinded-tokens]
            WHERE [token] IN (SELECT [token] FROM [invalid-unblinded-tokens])
            """,
        )

    @with_cursor
    def reset_unblinded_tokens(self, cursor, unblinded_tokens):
        """
        Make some unblinded tokens available to be retrieved from the store again.
        This is useful if a spending operation has failed with a transient
        error.
        """
        cursor.executemany(
            """
            INSERT INTO [to-reset] VALUES (?)
            """,
            list(
                (token.unblinded_token.decode("ascii"),) for token in unblinded_tokens
            ),
        )
        cursor.execute(
            """
            DELETE FROM [in-use]
            WHERE [unblinded-token] IN [to-reset]
            """,
        )
        cursor.execute(
            """
            DELETE FROM [to-reset]
            """,
        )

    def start_lease_maintenance(self):
        """
        Get an object which can track a newly started round of lease maintenance
        activity.

        :return LeaseMaintenance: A new, started lease maintenance object.
        """
        m = LeaseMaintenance(self.pass_value, self.now, self._connection)
        m.start()
        return m

    @with_cursor
    def get_latest_lease_maintenance_activity(self, cursor):
        """
        Get a description of the most recently completed lease maintenance
        activity.

        :return LeaseMaintenanceActivity|None: If any lease maintenance has
            completed, an object describing its results.  Otherwise, None.
        """
        cursor.execute(
            """
            SELECT [started], [count], [finished]
            FROM [lease-maintenance-spending]
            WHERE [finished] IS NOT NULL
            ORDER BY [finished] DESC
            LIMIT 1
            """,
        )
        activity = cursor.fetchall()
        if len(activity) == 0:
            return None
        [(started, count, finished)] = activity
        return LeaseMaintenanceActivity(
            parse_datetime(started, delimiter=" "),
            count,
            parse_datetime(finished, delimiter=" "),
        )


@implementer(ILeaseMaintenanceObserver)
@attr.s
class LeaseMaintenance(object):
    """
    A state-updating helper for recording pass usage during a lease
    maintenance run.

    Get one of these from ``VoucherStore.start_lease_maintenance``.  Then use
    the ``observe`` and ``finish`` methods to persist state about a lease
    maintenance run.

    :ivar int _pass_value: The value of a single ZKAP in byte-months.

    :ivar _now: A no-argument callable which returns a datetime giving a time
        to use as current.

    :ivar _connection: A SQLite3 connection object to use to persist observed
        information.

    :ivar _rowid: None for unstarted lease maintenance objects.  For started
        objects, the database row id that corresponds to the started run.
        This is used to make sure future updates go to the right row.
    """

    _pass_value = pass_value_attribute()
    _now = attr.ib()
    _connection = attr.ib()
    _rowid = attr.ib(default=None)

    @with_cursor
    def start(self, cursor):
        """
        Record the start of a lease maintenance run.
        """
        if self._rowid is not None:
            raise Exception("Cannot re-start a particular _LeaseMaintenance.")

        cursor.execute(
            """
            INSERT INTO [lease-maintenance-spending] ([started], [finished], [count])
            VALUES (?, ?, ?)
            """,
            (self._now(), None, 0),
        )
        self._rowid = cursor.lastrowid

    @with_cursor
    def observe(self, cursor, sizes):
        """
        Record a storage shares of the given sizes.
        """
        count = required_passes(self._pass_value, sizes)
        cursor.execute(
            """
            UPDATE [lease-maintenance-spending]
            SET [count] = [count] + ?
            WHERE [id] = ?
            """,
            (count, self._rowid),
        )

    @with_cursor
    def finish(self, cursor):
        """
        Record the completion of this lease maintenance run.
        """
        cursor.execute(
            """
            UPDATE [lease-maintenance-spending]
            SET [finished] = ?
            WHERE [id] = ?
            """,
            (self._now(), self._rowid),
        )
        self._rowid = None


@attr.s
class LeaseMaintenanceActivity(object):
    started = attr.ib()
    passes_required = attr.ib()
    finished = attr.ib()


# store = ...
# x = store.start_lease_maintenance()
# x.observe(size=123)
# x.observe(size=456)
# ...
# x.finish()
#
# x = store.get_latest_lease_maintenance_activity()
# xs.started, xs.passes_required, xs.finished


@attr.s(frozen=True)
class UnblindedToken(object):
    """
    An ``UnblindedToken`` instance represents cryptographic proof of a voucher
    redemption.  It is an intermediate artifact in the PrivacyPass protocol
    and can be used to construct a privacy-preserving pass which can be
    exchanged for service.

    :ivar bytes unblinded_token: The base64 encoded serialized form of the
        unblinded token.  This can be used to reconstruct a
        ``challenge_bypass_ristretto.UnblindedToken`` using that class's
        ``decode_base64`` method.
    """

    unblinded_token = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(bytes),
            is_base64_encoded(),
            has_length(128),
        ),
    )


@attr.s(frozen=True)
class Pass(object):
    """
    A ``Pass`` instance completely represents a single Zero-Knowledge Access Pass.

    :ivar bytes pass_bytes: The text value of the pass.  This can be sent to
        a service provider one time to anonymously prove a prior voucher
        redemption.  If it is sent more than once the service provider may
        choose to reject it and the anonymity property is compromised.  Pass
        text should be kept secret.  If pass text is divulged to third-parties
        the anonymity property may be compromised.
    """

    preimage = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(bytes),
            is_base64_encoded(),
            has_length(88),
        ),
    )

    signature = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(bytes),
            is_base64_encoded(),
            has_length(88),
        ),
    )

    @property
    def pass_bytes(self):
        return b" ".join((self.preimage, self.signature))

    @classmethod
    def from_bytes(cls, pass_):
        return cls(*pass_.split(b" "))


@attr.s(frozen=True)
class RandomToken(object):
    """
    :ivar bytes token_value: The base64-encoded representation of the random
        token.
    """

    token_value = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(bytes),
            is_base64_encoded(),
            has_length(128),
        ),
    )


def _counter_attribute():
    return attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(int),
            greater_than(-1),
        ),
    )


@attr.s(frozen=True)
class Pending(object):
    """
    The voucher has not yet been completely redeemed for ZKAPs.

    :ivar int counter: The number of partial redemptions which have been
        successfully performed for the voucher.
    """

    counter = _counter_attribute()

    def should_start_redemption(self):
        return True

    def to_json_v1(self):
        return {
            "name": "pending",
            "counter": self.counter,
        }


@attr.s(frozen=True)
class Redeeming(object):
    """
    This is a non-persistent state in which a voucher exists when the database
    state is **pending** but for which there is a redemption operation in
    progress.
    """

    started = attr.ib(validator=attr.validators.instance_of(datetime))
    counter = _counter_attribute()

    def should_start_redemption(self):
        return False

    def to_json_v1(self):
        return {
            "name": "redeeming",
            "started": self.started.isoformat(),
            "counter": self.counter,
        }


@attr.s(frozen=True)
class Redeemed(object):
    """
    The voucher was successfully redeemed.  Associated tokens were retrieved
    and stored locally.

    :ivar datetime finished: The time when the redemption finished.

    :ivar int token_count: The number of tokens the voucher was redeemed for.
    """

    finished = attr.ib(validator=attr.validators.instance_of(datetime))
    token_count = attr.ib(validator=attr.validators.instance_of(int))

    def should_start_redemption(self):
        return False

    def to_json_v1(self):
        return {
            "name": "redeemed",
            "finished": self.finished.isoformat(),
            "token-count": self.token_count,
        }


@attr.s(frozen=True)
class DoubleSpend(object):
    finished = attr.ib(validator=attr.validators.instance_of(datetime))

    def should_start_redemption(self):
        return False

    def to_json_v1(self):
        return {
            "name": "double-spend",
            "finished": self.finished.isoformat(),
        }


@attr.s(frozen=True)
class Unpaid(object):
    """
    This is a non-persistent state in which a voucher exists when the database
    state is **pending** but the most recent redemption attempt has failed due
    to lack of payment.
    """

    finished = attr.ib(validator=attr.validators.instance_of(datetime))

    def should_start_redemption(self):
        return True

    def to_json_v1(self):
        return {
            "name": "unpaid",
            "finished": self.finished.isoformat(),
        }


@attr.s(frozen=True)
class Error(object):
    """
    This is a non-persistent state in which a voucher exists when the database
    state is **pending** but the most recent redemption attempt has failed due
    to an error that is not handled by any other part of the system.
    """

    finished = attr.ib(validator=attr.validators.instance_of(datetime))
    details = attr.ib(validator=attr.validators.instance_of(str))

    def should_start_redemption(self):
        return True

    def to_json_v1(self):
        return {
            "name": "error",
            "finished": self.finished.isoformat(),
            "details": self.details,
        }


@attr.s(frozen=True)
class Voucher(object):
    """
    :ivar bytes number: The byte string which gives this voucher its
        identity.

    :ivar datetime created: The time at which this voucher was added to this
        node.

    :ivar expected_tokens: The total number of tokens for which we expect to
        be able to redeem this voucher.  Tokens are redeemed in smaller
        groups, progress of which is tracked in ``state``.  This only gives
        the total we expect to reach at completion.

    :ivar state: An indication of the current state of this voucher.  This is
        an instance of ``Pending``, ``Redeeming``, ``Redeemed``,
        ``DoubleSpend``, ``Unpaid``, or ``Error``.
    """

    number = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(bytes),
            is_base64_encoded(urlsafe_b64decode),
            has_length(44),
        ),
    )

    expected_tokens = attr.ib(
        validator=attr.validators.optional(
            attr.validators.and_(
                attr.validators.instance_of(int),
                greater_than(0),
            ),
        ),
    )

    created = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(datetime)),
    )

    state = attr.ib(
        default=Pending(counter=0),
        validator=attr.validators.instance_of(
            (
                Pending,
                Redeeming,
                Redeemed,
                DoubleSpend,
                Unpaid,
                Error,
            )
        ),
    )

    @classmethod
    def from_row(cls, row):
        def state_from_row(state, row):
            if state == "pending":
                return Pending(counter=row[3])
            if state == "double-spend":
                return DoubleSpend(
                    parse_datetime(row[0], delimiter=" "),
                )
            if state == "redeemed":
                return Redeemed(
                    parse_datetime(row[0], delimiter=" "),
                    row[1],
                )
            raise ValueError("Unknown voucher state {}".format(state))

        number, created, expected_tokens, state = row[:4]

        return cls(
            number=number.encode("ascii"),
            expected_tokens=expected_tokens,
            # All Python datetime-based date/time libraries fail to handle
            # leap seconds.  This parse call might raise an exception of the
            # value represents a leap second.  However, since we also use
            # Python to generate the data in the first place, it should never
            # represent a leap second... I hope.
            created=parse_datetime(created, delimiter=" "),
            state=state_from_row(state, row[4:]),
        )

    @classmethod
    def from_json(cls, json):
        values = loads(json)
        version = values.pop("version")
        return getattr(cls, "from_json_v{}".format(version))(values)

    @classmethod
    def from_json_v1(cls, values):
        state_json = values["state"]
        state_name = state_json["name"]
        if state_name == "pending":
            state = Pending(counter=state_json["counter"])
        elif state_name == "redeeming":
            state = Redeeming(
                started=parse_datetime(state_json["started"]),
                counter=state_json["counter"],
            )
        elif state_name == "double-spend":
            state = DoubleSpend(
                finished=parse_datetime(state_json["finished"]),
            )
        elif state_name == "redeemed":
            state = Redeemed(
                finished=parse_datetime(state_json["finished"]),
                token_count=state_json["token-count"],
            )
        elif state_name == "unpaid":
            state = Unpaid(
                finished=parse_datetime(state_json["finished"]),
            )
        elif state_name == "error":
            state = Error(
                finished=parse_datetime(state_json["finished"]),
                details=state_json["details"],
            )
        else:
            raise ValueError("Unrecognized state {!r}".format(state_json))

        return cls(
            number=values["number"].encode("ascii"),
            expected_tokens=values["expected-tokens"],
            created=None
            if values["created"] is None
            else parse_datetime(values["created"]),
            state=state,
        )

    def to_json(self):
        return dumps_utf8(self.marshal())

    def marshal(self):
        return self.to_json_v1()

    def to_json_v1(self):
        state = self.state.to_json_v1()
        return {
            "number": self.number.decode("ascii"),
            "expected-tokens": self.expected_tokens,
            "created": None if self.created is None else self.created.isoformat(),
            "state": state,
            "version": 1,
        }
