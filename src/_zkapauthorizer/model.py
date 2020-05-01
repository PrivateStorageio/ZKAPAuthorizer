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
from zope.interface import (
    Interface,
    implementer,
)

from sqlite3 import (
    OperationalError,
    connect as _connect,
)

import attr

from aniso8601 import (
    parse_datetime,
)
from twisted.logger import (
    Logger,
)
from twisted.python.filepath import (
    FilePath,
)

from ._base64 import (
    urlsafe_b64decode,
)

from .validators import (
    is_base64_encoded,
    has_length,
    greater_than,
)

from .storage_common import (
    pass_value_attribute,
    get_configured_pass_value,
    required_passes,
)

from .schema import (
    get_schema_version,
    get_schema_upgrades,
    run_schema_upgrades,
)


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


CONFIG_DB_NAME = u"privatestorageio-zkapauthz-v1.sqlite3"

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
        actual_version = get_schema_version(cursor)
        schema_upgrades = list(get_schema_upgrades(actual_version))
        run_schema_upgrades(schema_upgrades, cursor)
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
        :param unicode voucher: The text value of a voucher to retrieve.

        :return Voucher: The voucher object that matches the given value.
        """
        cursor.execute(
            """
            SELECT
                [number], [created], [state], [finished], [token-count], [public-key], [counter]
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
    def add(self, cursor, voucher, get_tokens):
        """
        Add a new voucher and associated random tokens to the database.  If a
        voucher with the given text value is already present, do nothing.

        :param unicode voucher: The text value of a voucher to add.

        :param list[RandomToken]: The tokens to add alongside the voucher.
        """
        now = self.now()
        if not isinstance(now, datetime):
            raise TypeError("{} returned {}, expected datetime".format(self.now, now))

        cursor.execute("BEGIN IMMEDIATE TRANSACTION")
        cursor.execute(
            """
            SELECT ([text])
            FROM [tokens]
            WHERE [voucher] = ?
            """,
            (voucher,),
        )
        rows = cursor.fetchall()
        if len(rows) > 0:
            self._log.info(
                "Loaded {count} random tokens for a voucher ({voucher}).",
                count=len(rows),
                voucher=voucher,
            )
            tokens = list(
                RandomToken(token_value)
                for (token_value,)
                in rows
            )
        else:
            tokens = get_tokens()
            self._log.info(
                "Persisting {count} random tokens for a voucher ({voucher}).",
                count=len(tokens),
                voucher=voucher,
            )
            cursor.execute(
                """
                INSERT OR IGNORE INTO [vouchers] ([number], [created]) VALUES (?, ?)
                """,
                (voucher, self.now())
            )
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
        cursor.connection.commit()
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
                [number], [created], [state], [finished], [token-count], [public-key], [counter]
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

    def _insert_unblinded_tokens(self, cursor, unblinded_tokens):
        """
        Helper function to really insert unblinded tokens into the database.
        """
        cursor.executemany(
            """
            INSERT INTO [unblinded-tokens] VALUES (?)
            """,
            list(
                (token,)
                for token
                in unblinded_tokens
            ),
        )

    @with_cursor
    def insert_unblinded_tokens(self, cursor, unblinded_tokens):
        """
        Store some unblinded tokens, for example as part of a backup-restore
        process.

        :param list[unicode] unblinded_tokens: The unblinded tokens to store.
        """
        self._insert_unblinded_tokens(cursor, unblinded_tokens)

    @with_cursor
    def insert_unblinded_tokens_for_voucher(self, cursor, voucher, public_key, unblinded_tokens):
        """
        Store some unblinded tokens received from redemption of a voucher.

        :param unicode voucher: The voucher associated with the unblinded
            tokens.  This voucher will be marked as redeemed to indicate it
            has fulfilled its purpose and has no further use for us.

        :param unicode public_key: The encoded public key for the private key
            which was used to sign these tokens.

        :param list[UnblindedToken] unblinded_tokens: The unblinded tokens to
            store.
        """
        voucher_state = u"redeemed"
        cursor.execute(
            """
            UPDATE [vouchers]
            SET [state] = ?
              , [token-count] = ?
              , [finished] = ?
              , [public-key] = ?
            WHERE [number] = ?
            """,
            (
                voucher_state,
                len(unblinded_tokens),
                self.now(),
                public_key,
                voucher,
            ),
        )
        if cursor.rowcount == 0:
            raise ValueError("Cannot insert tokens for unknown voucher; add voucher first")
        self._insert_unblinded_tokens(
            cursor,
            list(
                t.unblinded_token
                for t
                in unblinded_tokens
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
            SELECT COUNT(token)
            FROM [unblinded-tokens]
            """,
        )
        [(existing_tokens,)] = cursor.fetchall()
        if existing_tokens < count:
            raise NotEnoughTokens()

        cursor.execute(
            """
            CREATE TEMPORARY TABLE [extracting]
            AS
            SELECT [token] FROM [unblinded-tokens] LIMIT ?
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
            SELECT [token] FROM [unblinded-tokens]
            """,
        )
        tokens = cursor.fetchall()
        return {
            u"unblinded-tokens": list(token for (token,) in tokens),
        }

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
            parse_datetime(started, delimiter=u" "),
            count,
            parse_datetime(finished, delimiter=u" "),
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

    :ivar unicode unblinded_token: The base64 encoded serialized form of the
        unblinded token.  This can be used to reconstruct a
        ``challenge_bypass_ristretto.UnblindedToken`` using that class's
        ``decode_base64`` method.
    """
    unblinded_token = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(unicode),
            is_base64_encoded(),
            has_length(128),
        ),
    )


@attr.s(frozen=True)
class Pass(object):
    """
    A ``Pass`` instance completely represents a single Zero-Knowledge Access Pass.

    :ivar unicode pass_text: The text value of the pass.  This can be sent to
        a service provider one time to anonymously prove a prior voucher
        redemption.  If it is sent more than once the service provider may
        choose to reject it and the anonymity property is compromised.  Pass
        text should be kept secret.  If pass text is divulged to third-parties
        the anonymity property may be compromised.
    """
    preimage = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(unicode),
            is_base64_encoded(),
            has_length(88),
        ),
    )

    signature = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(unicode),
            is_base64_encoded(),
            has_length(88),
        ),
    )

    @property
    def pass_text(self):
        return u"{} {}".format(self.preimage, self.signature)


@attr.s(frozen=True)
class RandomToken(object):
    """
    :ivar unicode token_value: The base64-encoded representation of the random
        token.
    """
    token_value = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(unicode),
            is_base64_encoded(),
            has_length(128),
        ),
    )


def _counter_attribute():
    return attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of((int, long)),
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
            u"name": u"pending",
            u"counter": self.counter,
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
            u"name": u"redeeming",
            u"started": self.started.isoformat(),
        }


@attr.s(frozen=True)
class Redeemed(object):
    """
    The voucher was successfully redeemed.  Associated tokens were retrieved
    and stored locally.

    :ivar datetime finished: The time when the redemption finished.

    :ivar int token_count: The number of tokens the voucher was redeemed for.

    :ivar unicode public_key: The public part of the key used to sign the
        tokens for this voucher.
    """
    finished = attr.ib(validator=attr.validators.instance_of(datetime))
    token_count = attr.ib(validator=attr.validators.instance_of((int, long)))
    public_key = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(unicode)))

    def should_start_redemption(self):
        return False

    def to_json_v1(self):
        return {
            u"name": u"redeemed",
            u"finished": self.finished.isoformat(),
            u"token-count": self.token_count,
            u"public-key": self.public_key,
        }


@attr.s(frozen=True)
class DoubleSpend(object):
    finished = attr.ib(validator=attr.validators.instance_of(datetime))

    def should_start_redemption(self):
        return False

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

    def should_start_redemption(self):
        return True

    def to_json_v1(self):
        return {
            u"name": u"unpaid",
            u"finished": self.finished.isoformat(),
        }


@attr.s(frozen=True)
class Error(object):
    """
    This is a non-persistent state in which a voucher exists when the database
    state is **pending** but the most recent redemption attempt has failed due
    to an error that is not handled by any other part of the system.
    """
    finished = attr.ib(validator=attr.validators.instance_of(datetime))
    details = attr.ib(validator=attr.validators.instance_of(unicode))

    def should_start_redemption(self):
        return True

    def to_json_v1(self):
        return {
            u"name": u"error",
            u"finished": self.finished.isoformat(),
            u"details": self.details,
        }


@attr.s(frozen=True)
class Voucher(object):
    """
    :ivar unicode number: The text string which gives this voucher its
        identity.

    :ivar datetime created: The time at which this voucher was added to this
        node.

    :ivar state: An indication of the current state of this voucher.  This is
        an instance of ``Pending``, ``Redeeming``, ``Redeemed``,
        ``DoubleSpend``, ``Unpaid``, or ``Error``.
    """
    number = attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(unicode),
            is_base64_encoded(urlsafe_b64decode),
            has_length(44),
        ),
    )
    created = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(datetime)),
    )
    state = attr.ib(
        default=Pending(counter=0),
        validator=attr.validators.instance_of((
            Pending,
            Redeeming,
            Redeemed,
            DoubleSpend,
            Unpaid,
            Error,
        )),
    )

    @classmethod
    def from_row(cls, row):
        def state_from_row(state, row):
            if state == u"pending":
                # TODO: The 0 here should be row[3] but I can't write a test
                # to prove it yet.
                return Pending(counter=0)
            if state == u"double-spend":
                return DoubleSpend(
                    parse_datetime(row[0], delimiter=u" "),
                )
            if state == u"redeemed":
                return Redeemed(
                    parse_datetime(row[0], delimiter=u" "),
                    row[1],
                    row[2],
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
            state = Pending(counter=state_json[u"counter"])
        elif state_name == u"redeeming":
            state = Redeeming(
                started=parse_datetime(state_json[u"started"]),
                counter=0,
            )
        elif state_name == u"double-spend":
            state = DoubleSpend(
                finished=parse_datetime(state_json[u"finished"]),
            )
        elif state_name == u"redeemed":
            state = Redeemed(
                finished=parse_datetime(state_json[u"finished"]),
                token_count=state_json[u"token-count"],
                public_key=state_json[u"public-key"],
            )
        elif state_name == u"unpaid":
            state = Unpaid(
                finished=parse_datetime(state_json[u"finished"]),
            )
        elif state_name == u"error":
            state = Error(
                finished=parse_datetime(state_json[u"finished"]),
                details=state_json[u"details"],
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
