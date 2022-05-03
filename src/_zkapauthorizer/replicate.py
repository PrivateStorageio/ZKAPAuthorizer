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

from __future__ import annotations

"""
A system for replicating local SQLite3 database state to remote storage.

Theory of Operation
===================

A function to wrap a ``sqlite3.Connection`` in a new type is provided.  This
new type provides facilities for accomplishing two goals:

* It (can someday) presents an expanded connection interface which includes
  the ability to switch the database into "replicated" mode.  This is an
  application-facing interface meant to be used when the application is ready
  to discharge its responsibilities in the replication process.

* It (can someday) expose the usual cursor interface wrapped around the usual
  cursor behavior combined with extra logic to record statements which change
  the underlying database (DDL and DML statements).  This recorded data then
  feeds into the above replication process once it is enabled.

An application's responsibilities in the replication process are to arrange
for remote storage of "snapshots" and "event streams".  See the
replication/recovery design document for details of these concepts.

Once replication has been enabled, the application (can someday be) informed
whenever the event stream changes (respecting database transactionality) and
data can be shipped to remote storage as desired.

It is essential to good replication performance that once replication is
enabled all database-modifying actions are captured in the event stream.  This
is the reason for providing a ``sqlite3.Connection``-like object for use by
application code rather than a separate side-car interface: it minimizes the
opportunities for database changes which are overlooked by this replication
system.
"""

__all__ = [
    "ReplicationAlreadySetup",
    "fail_setup_replication",
    "setup_tahoe_lafs_replication",
    "with_replication",
    "statements_to_snapshot",
    "connection_to_statements",
    "snapshot",
]

from io import BytesIO
from sqlite3 import Connection as _SQLite3Connection
from sqlite3 import Cursor as _SQLite3Cursor
from typing import (
    Any,
    Awaitable,
    BinaryIO,
    Callable,
    Generator,
    Iterable,
    Iterator,
    Optional,
    Sequence,
)

import cbor2
from attrs import Factory, define, field, frozen
from compose import compose
from twisted.application.service import IService, Service
from twisted.internet.defer import CancelledError, Deferred, DeferredSemaphore, succeed
from twisted.python.failure import Failure
from twisted.python.filepath import FilePath
from twisted.python.lockfile import FilesystemLock

from ._types import CapStr
from .config import REPLICA_RWCAP_BASENAME, Config
from .sql import Connection, Cursor, SQLType, bind_arguments, statement_mutates
from .tahoe import ITahoeClient, attenuate_writecap

# function which can set remote ZKAPAuthorizer state.
Uploader = Callable[[str, Callable[[], BinaryIO]], Awaitable[None]]


@frozen
class Change:
    """
    Represent an item in a replication event stream
    """

    sequence: int  # the sequence-number of this event
    statement: str  # the SQL statement string


@frozen
class EventStream:
    """
    A series of database operations represented as `Change` instances.
    """

    changes: tuple[Change, ...]

    def highest_sequence(self) -> Optional[int]:
        """
        :returns: the highest sequence number in this EventStream (or
            None if there are no events)
        """
        if not self.changes:
            return None
        return max(change.sequence for change in self.changes)

    def to_bytes(self) -> BinaryIO:
        """
        :returns BinaryIO: a producer of bytes representing this EventStream.
        """
        return BytesIO(
            cbor2.dumps(
                {
                    "events": tuple(
                        (event.sequence, event.statement.encode("utf8"))
                        for event in self.changes
                    )
                }
            )
        )

    @classmethod
    def from_bytes(cls, stream: BinaryIO):
        """
        :returns EventStream: an instance of EventStream from the given
            bytes (which should have been produced by a prior call to
            ``to_bytes``)
        """
        data = cbor2.load(stream)
        return cls(
            changes=tuple(
                Change(seq, statement.decode("utf8"))
                for seq, statement in data["events"]
            )
        )


class AlreadySettingUp(Exception):
    """
    Another setup attempt is currently in progress.
    """


class ReplicationAlreadySetup(Exception):
    """
    An attempt was made to setup of replication but it is already set up.
    """


async def fail_setup_replication():
    """
    A replication setup function that always fails.
    """
    raise Exception("Test not set up for replication")


async def setup_tahoe_lafs_replication(client: ITahoeClient) -> str:
    """
    Configure the ZKAPAuthorizer plugin that lives in the Tahoe-LAFS node with
    the given configuration to replicate its state onto Tahoe-LAFS storage
    servers using that Tahoe-LAFS node.
    """
    # Find the configuration path for this node's replica.
    config_path = client.get_private_path(REPLICA_RWCAP_BASENAME)

    # Take an advisory lock on the configuration path to avoid concurrency
    # shennanigans.
    config_lock = FilesystemLock(config_path.asTextMode().path + ".lock")

    if not config_lock.lock():
        raise AlreadySettingUp()
    try:

        # Check to see if there is already configuration.
        if config_path.exists():
            raise ReplicationAlreadySetup()

        # Create a directory with it
        rw_cap = await client.make_directory()

        # Store the resulting write-cap in the node's private directory
        config_path.setContent(rw_cap.encode("ascii"))

    finally:
        # On success and failure, release the lock since we're done with the
        # file for now.
        config_lock.unlock()

    # Attenuate it to a read-cap
    rocap = attenuate_writecap(rw_cap)

    # Return the read-cap
    return rocap


def is_replication_setup(config: Config) -> bool:
    """
    :return: ``True`` if and only if replication has previously been setup for
        the Tahoe-LAFS node associated with the given configuration.
    """
    # Find the configuration path for this node's replica.
    return FilePath(config.get_private_path(REPLICA_RWCAP_BASENAME)).exists()


def get_replica_rwcap(config: Config) -> CapStr:
    """
    :return: a mutable directory capability for our replica.
    :raises: Exception if replication is not setup
    """
    rwcap_file = FilePath(config.get_private_path(REPLICA_RWCAP_BASENAME))
    return rwcap_file.getContent()


@define
class _Important:
    """
    A context-manager to set and unset the ._important flag on a
    _ReplicationCapableConnection
    """

    _replication_cursor: _ReplicationCapableCursor

    def __enter__(self) -> None:
        self._replication_cursor._important = True

    def __exit__(self, *args) -> None:
        self._replication_cursor._important = False
        return None


def with_replication(
    connection: _SQLite3Connection, enable_replication: bool
) -> _ReplicationCapableConnection:
    """
    Wrap the given connection in a layer which is capable of entering a
    "replication mode".  In replication mode, the wrapper stores all changes
    made through the connection so that they are available to be replicated by
    another component.  In normal mode, changes are not stored.

    :param connection: The SQLite3 connection to wrap.

    :param enable_replication: If ``True`` then the wrapper is placed in
        "replication mode" initially.  Otherwise it is not but it can be
        switched into that mode later.

    :return: The wrapper object.
    """
    return _ReplicationCapableConnection(connection, enable_replication)


Mutation = tuple[bool, str, Sequence[tuple[SQLType, ...]]]
MutationObserver = Callable[[_SQLite3Cursor, Sequence[Mutation]], Callable[[], None]]


@define
class _ReplicationCapableConnection:
    """
    Wrap a ``sqlite3.Connection`` to provide additional snapshot- and
    streaming replication-related features.

    All of this type's methods are intended to behave the same way as
    ``sqlite3.Connection``\ 's methods except they may also add some
    additional functionality to support replication.

    :ivar _replicating: ``True`` if this connection is currently in
        replication mode and is recording all executed DDL and DML statements,
        ``False`` otherwise.
    """

    # the "real" / normal sqlite connection
    _conn: _SQLite3Connection
    _replicating: bool
    _observers: tuple = Factory(tuple)
    _mutations: list = Factory(list)

    def enable_replication(self) -> None:
        """
        Turn on replication support.
        """
        self._replicating = True

    def add_mutation_observer(self, fn: MutationObserver) -> None:
        self._observers = self._observers + (fn,)

    def iterdump(self) -> Iterator[str]:
        """
        :return: SQL statements which can be used to reconstruct the database
            state.
        """
        return self._conn.iterdump()

    # XXX there is a "commit" method too?

    def close(self) -> None:
        return self._conn.close()

    def __enter__(self) -> _ReplicationCapableConnection:
        self._conn.__enter__()
        return self

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_value: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> bool:
        propagate = self._conn.__exit__(exc_type, exc_value, exc_tb)
        if exc_type is None:
            # There was no exception, signal observers that a change has been
            # committed.
            post_txn_fns: list[Callable[[], None]] = []
            with self._conn:
                curse = self._conn.cursor()
                curse.execute("BEGIN IMMEDIATE TRANSACTION")
                post_txn_fns.extend(self._maybe_signal_observers(curse))
            for f in post_txn_fns:
                f()
        # Respect the underlying propagation decision.
        return propagate

    def _maybe_signal_observers(
        self, cursor
    ) -> Generator[Callable[[], None], None, None]:
        if self._mutations:
            to_signal = self._mutations
            self._mutations = list()
            for ob in self._observers:
                yield ob(cursor, to_signal)

    def cursor(self, factory: Optional[type] = None) -> Cursor:
        kwargs = {}
        if factory is not None:
            kwargs["factory"] = factory
        cursor = self._conn.cursor(**kwargs)
        # this cursor honors the ._replicating flag in this instance
        return _ReplicationCapableCursor(cursor, self)


@define
class _ReplicationCapableCursor:
    """
    Wrap a ``sqlite3.Cursor`` to provide additional streaming
    replication-related features.

    All of this type's attributes and methods are intended to behave the same
    way as ``sqlite3.Cursor``\ 's methods except they may also add some
    additional functionality to support replication.
    """

    _cursor: _SQLite3Cursor
    _connection: _ReplicationCapableConnection
    # true while statements are "important" (which is pased along to
    # the observers and interpreted as being "important data that the
    # user will be interested in preserving")
    _important: bool = field(default=False)

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        return self._cursor.close()

    def execute(self, statement: str, row: Iterable[Any] = ()) -> Cursor:
        """
        sqlite's Cursor API

        :param row: the arguments
        """
        self._cursor.execute(statement, row)
        if self._connection._replicating and statement_mutates(statement):
            # note that this interface is for multiple statements, so
            # we turn our single row into a one-tuple
            self._connection._mutations.append((self._important, statement, (row,)))
        return self

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, n):
        return self._cursor.fetchmany(n)

    def fetchone(self):
        return self._cursor.fetchone()

    def executemany(self, statement: str, rows: Iterable[Any]) -> Cursor:
        self._cursor.executemany(statement, rows)
        if self._connection._replicating and statement_mutates(statement):
            self._connection._mutations.append((self._important, statement, rows))
        return self

    def important(self) -> _Important:
        """
        Create a new context-manager that -- while active -- sets the
        'important' flag to true and resets it afterwards.
        """
        return _Important(self)


def netstring(bs: bytes) -> bytes:
    """
    Encode a single string as a netstring.

    :see: http://cr.yp.to/proto/netstrings.txt
    """
    return b"".join(
        [
            str(len(bs)).encode("ascii"),
            b":",
            bs,
            b",",
        ]
    )


def statements_to_snapshot(statements: Iterator[str]) -> Iterator[bytes]:
    """
    Take a snapshot of the database reachable via the given connection.

    The snapshot is consistent and write transactions on the given connection
    are blocked until it has been completed.
    """
    for statement in statements:
        # Use netstrings to frame each statement.  Statements can have
        # embedded newlines (and CREATE TABLE statements especially tend to).
        yield netstring(statement.strip().encode("utf-8"))


def connection_to_statements(connection: Connection) -> Iterator[str]:
    """
    Create an iterator of SQL statements as strings representing a consistent,
    self-contained snapshot of the database reachable via the given
    connection.
    """
    return iter(connection.iterdump())


# Convenience API to dump statements, netstring-encoding them, and
# concatenating them all into a single byte string.
snapshot: Callable[[Connection], bytes] = compose(
    b"".join, statements_to_snapshot, connection_to_statements
)


async def tahoe_lafs_uploader(
    client: ITahoeClient,
    recovery_cap: str,
    get_snapshot_data: Callable[[], BinaryIO],
    entry_name: str,
) -> None:
    """
    Upload a replica to Tahoe, linking the result into the given
    recovery mutable capbility under the name 'snapshot.sql'
    """
    snapshot_immutable_cap = await client.upload(get_snapshot_data)
    await client.link(recovery_cap, entry_name, snapshot_immutable_cap)


def get_tahoe_lafs_direntry_uploader(
    client: ITahoeClient,
    directory_mutable_cap: str,
):
    """
    Bind a Tahoe client to a mutable directory in a callable that will
    upload some data and link it into the mutable directory under the
    given name.

    :return Callable[[str, Callable[[], BinaryIO]], Awaitable[None]]:
        A callable that will upload some data as the latest replica
        snapshot. The data isn't given directly, but instead from a
        zero-argument callable itself to facilitate retrying.
    """

    async def upload(
        entry_name: str, get_data_provider: Callable[[], BinaryIO]
    ) -> None:
        await tahoe_lafs_uploader(
            client, directory_mutable_cap, get_data_provider, entry_name
        )

    return upload


def add_event(cursor: SQLite3Cursor, sql_statement: str) -> None:
    """
    Add a new change to the event-log.
    """
    cursor.execute(
        """
        INSERT INTO [event-stream]([statement]) VALUES (?)
        """,
        (sql_statement,),
    )

def get_events(cursor: _SQLite3Cursor) -> EventStream:
    """
    Return all events currently in our event-log.
    """
    cursor.execute(
        """
        SELECT [sequence-number], [statement]
        FROM [event-stream]
        """
    )
    rows = cursor.fetchall()
    return EventStream(changes=tuple(Change(seq, stmt) for seq, stmt in rows))

def prune_events_to(cursor: _SQLite3Cursor, sequence_number: int) -> None:
    """
    Remove all events <= sequence_number
    """
    cursor.execute(
        """
        DELETE FROM [event-stream]
        WHERE [sequence-number] <= (?)
        """,
        (sequence_number,),
    )
    cursor.fetchall()


@define
class _ReplicationService(Service):
    """
    Perform all activity related to maintaining a remote replica of the local
    ZKAPAuthorizer database.

    :ivar _connection: A connection to the database being replicated.

    :ivar _replicating: The long-running replication operation.  This is never
        expected to complete but it will be cancelled when the service stops.
    """

    name = "replication-service"  # type: ignore # Service assigns None, screws up type inference

    _connection: _ReplicationCapableConnection = field()
    _private_connection: _SQLite3Connection = field()
    _store: VoucherStore
    _uploader: Uploader
    _replicating: Optional[Deferred] = field(init=False, default=None)

    _accumulated_size: int = 0
    _trigger: DeferredSemaphore = Factory(lambda: DeferredSemaphore(1))

    def startService(self) -> None:
        super().startService()

        self._connection.enable_replication()

        # restore our state .. this number will be bigger than what we
        # would have recorded through "normal" means which only counts
        # the statement-sizes .. but maybe fine?
        with self._connection._conn:
            events = get_events(self._connection._conn.cursor())
        self._accumulated_size = len(events.to_bytes().getvalue())

        # should we do an upload immediately? or hold the lock?
        if not self.big_enough():
            self._trigger.acquire()

        # Tell the store to initiate replication when appropriate.  The
        # service should only be created and started if replication has been
        # turned on - so, make sure replication is turned on at the database
        # layer.
        self._replicating = Deferred.fromCoroutine(self.wait_for_uploads())

        def catch_cancelled(err: Failure) -> None:
            """
            Ignore cancels; this will be the normal way we quit -- see stopService
            """
            err.trap(CancelledError)
            return None

        self._replicating.addErrback(catch_cancelled)
        # if something besides a "cancel" happens, do something with it
        self._replicating.addErrback(self._replication_fail)
        self._connection.add_mutation_observer(self.observed_event)

    def _replication_fail(self, fail: Failure) -> None:
        """
        Replicating has failed for some reason
        """
        print(f"Replication failure: {fail}")

    def queue_upload(self) -> None:
        """
        Ask for an upload to occur
        """
        if self._trigger.tokens == 0:
            self._trigger.release()
        else:
            # we're already uploading
            pass

    async def wait_for_uploads(self) -> None:
        """
        An infinite async loop that processes uploads
        """
        while True:
            await self._trigger.acquire()
            # note that errors in here mean our "forever loop" will
            # stop .. so we might want to simply log all/most errors
            # instead?
            await self._do_one_upload()

    async def _do_one_upload(self) -> None:
        """
        Process a single upload.
        """
        with self._connection._conn:
            events = get_events(self._connection._conn.cursor())

        # upload latest event-stream
        await self._uploader(
            "event-stream-{}".format(events.highest_sequence()),
            events.to_bytes,
        )

        # prune the database
        with self._private_connection:
            curse = self._connection._conn.cursor()
            prune_events_to(curse, events.highest_sequence())

    def stopService(self) -> Deferred[None]:
        """
        Cancel the replication operation and then wait for it to complete.
        """
        super().stopService()

        replicating = self._replicating
        if replicating is None:
            return succeed(None)

        self._replicating = None
        replicating.cancel()
        return replicating

    def observed_event(
        self,
        unobserved_cursor: _SQLite3Cursor,
        all_changes: Sequence[Mutation],
    ) -> Callable[[], None]:
        """
        A mutating SQL statement was observed by the cursor. This is like
        the executemany interface: there is always a list of args. For
        a single statement, we call this with the len(args) == 1

        :param all_changes: 3-tuples of (important, statement, args)
            where important is whether this should trigger an
            immediate upload; statement is the SQL statement; and args
            are the arguments for the SQL.
        """
        any_importants = False
        for (important, statement, list_of_args) in all_changes:
            for args in list_of_args:
                bound_statement = bind_arguments(unobserved_cursor, statement, args)
                add_event(unobserved_cursor, bound_statement)
                # note that we're ignoring a certain amount of size overhead
                # here: the _actual_ size will be some CBOR information and
                # the sequence number, although the statement text should
                # still dominate.
                self._accumulated_size += len(bound_statement)
            if important:
                any_importants = True
        if any_importants or self.big_enough():
            return self._complete_upload
        else:
            return lambda: None

    def _complete_upload(self) -> None:
        """
        This is called after the transaction closes (because we return it
        from our observer function). See
        _ReplicationCapableConnection.__exit__
        """
        self.queue_upload()
        self._accumulated_size = 0

    def big_enough(self) -> bool:
        """
        :returns: True if we have accumulated enough statements to upload
            an event-stream record.
        """
        return self._accumulated_size >= 570000


def replication_service(
    replicated_connection: _ReplicationCapableConnection,
    private_connection: _SQLite3Connection,
    store: VoucherStore,
    uploader: Uploader,
) -> IService:
    """
    Return a service which implements the replication process documented in
    the ``backup-recovery`` design document.
    """
    return _ReplicationService(
        connection=replicated_connection,
        private_connection=private_connection,
        store=store,
        uploader=uploader,
    )
