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

import os
import re
from enum import Enum
from io import BytesIO
from sqlite3 import Connection as _SQLite3Connection
from sqlite3 import Cursor as _SQLite3Cursor
from typing import (
    IO,
    Any,
    Awaitable,
    Callable,
    ClassVar,
    Generator,
    Iterable,
    Iterator,
    Optional,
    Protocol,
    Sequence,
)

import cbor2
from attrs import Factory, define, field, frozen
from compose import compose
from eliot import log_call
from twisted.application.service import IService, Service
from twisted.internet.defer import CancelledError, Deferred, DeferredQueue, succeed
from twisted.logger import Logger
from twisted.python.filepath import FilePath
from twisted.python.lockfile import FilesystemLock

from ._types import CapStr
from .config import REPLICA_RWCAP_BASENAME, Config
from .sql import Connection, Cursor, SQLRuntimeType, SQLType, statement_mutates
from .tahoe import (
    DataProvider,
    DirectoryEntry,
    ITahoeClient,
    attenuate_writecap,
    capability_from_string,
)

# function which can set remote ZKAPAuthorizer state.
Uploader = Callable[[str, DataProvider], Awaitable[None]]

# function which can remove entries from ZKAPAuthorizer state.
Pruner = Callable[[Callable[[str], bool]], Awaitable[None]]

# functions which can list all entries in ZKAPAuthorizer state
Lister = Callable[[], Awaitable[list[str]]]
EntryLister = Callable[[], Awaitable[dict[str, DirectoryEntry]]]


class SnapshotPolicy(Protocol):
    """
    Encode policy rules about when to take and upload a new snapshot.
    """

    def should_snapshot(self, snapshot_size: int, replica_sizes: list[int]) -> bool:
        """
        Given the size of a new snapshot and the size of an existing replica
        (snapshot and event streams), is now a good time to take a new
        snapshot?
        """


SNAPSHOT_NAME = "snapshot"


@frozen
class Replica:
    """
    Manage a specific replica.
    """

    upload: Uploader
    prune: Pruner
    entry_lister: EntryLister

    async def list(self) -> list[str]:
        return list(await self.entry_lister())


class ReplicationJob(Enum):
    """
    The kinds of jobs that the Replication queue knows about

    :ivar startup: The job that is run once when the replication service
        starts and which is responsible for inspecting local and remote state
        to determine if any actions are immediately necessary (even before any
        further local changes are made).

    :ivar event_stream: The job to upload a new event stream object.

    :ivar snapshot: The job to upload a new snapshot object and prune
        now-obsolete event stream objects.

    :ivar consider_snapshot: The job to inspect replica event stream and
        snapshot state and potentially schedule a new snapshot which will
        allow pruning of existing event streams.
    """

    startup = 1
    event_stream = 2
    snapshot = 3
    consider_snapshot = 4


@frozen
class Change:
    """
    Represent an item in a replication event stream

    :ivar sequence: The sequence number of this event.
    :ivar statement: The SQL statement associated with this event.
    :ivar important: Whether this change was "important" or not.
    :ivar arguments: Any arguments for the SQL statement.
    """

    sequence: int
    statement: str
    arguments: Sequence[SQLType] = field(converter=tuple)
    important: bool

    @arguments.validator
    def _validate_arguments(self, attribute, value) -> None:
        """
        Require that the value has as elements only values are legal SQL values.

        :note: attrs validators run after attrs converters.
        """
        if all(isinstance(o, SQLRuntimeType) for o in value):
            return None
        raise ValueError("sequence contains values incompatible with SQL")


@frozen
class EventStream:
    """
    A series of database operations represented as `Change` instances.

    :ivar version: An identifier for the schema of the serialized form of this
        event stream.  This will appear inside the serialized form.  A change
        to the schema will be accompanied with an increment to this value.
    """

    changes: Sequence[Change] = field(converter=tuple)
    version: ClassVar[int] = 1

    def highest_sequence(self) -> Optional[int]:
        """
        :returns: the highest sequence number in this EventStream (or
            None if there are no events)
        """
        if not self.changes:
            return None
        return max(change.sequence for change in self.changes)

    def to_bytes(self) -> IO[bytes]:
        """
        :returns: a producer of bytes representing this EventStream.
        """
        return BytesIO(
            cbor2.dumps(
                {
                    "version": self.version,
                    "events": tuple(
                        (
                            event.sequence,
                            event.statement,
                            event.arguments,
                            event.important,
                        )
                        for event in self.changes
                    ),
                }
            )
        )

    @classmethod
    def from_bytes(cls, stream: IO[bytes]) -> EventStream:
        """
        :returns EventStream: an instance of EventStream from the given
            bytes (which should have been produced by a prior call to
            ``to_bytes``)
        """
        data = cbor2.load(stream)
        serial_version = data.get("version", None)
        if serial_version != cls.version:
            raise ValueError(
                f"Unknown serialized event stream version {serial_version}"
            )
        return cls(
            changes=[
                # List comprehension has incompatible type List[Change]; expected List[_T_co]
                # https://github.com/python-attrs/attrs/issues/519
                Change(*args)  # type: ignore
                for args in data["events"]
            ]
        )


class AlreadySettingUp(Exception):
    """
    Another setup attempt is currently in progress.
    """


@define(auto_exc=False)
class ReplicationAlreadySetup(Exception):
    """
    An attempt was made to setup of replication but it is already set up.

    :ivar cap_str: The read-only capability of the replica that was already
        set up.
    """

    cap_str: str


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
            rwcap_obj = capability_from_string(config_path.getContent())
            rocap_str = rwcap_obj.get_readonly().to_string().decode("ascii")
            raise ReplicationAlreadySetup(rocap_str)

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
    return rwcap_file.getContent().decode("ascii")


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


Mutation = tuple[bool, str, Iterable[tuple[SQLType, ...]]]
MutationObserver = Callable[[_SQLite3Cursor, Iterable[Mutation]], Callable[[], None]]


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
    _observers: tuple[MutationObserver, ...] = Factory(tuple)
    _mutations: list[Mutation] = Factory(list)

    def enable_replication(self) -> None:
        """
        Turn on replication support.
        """
        self._replicating = True

    def add_mutation_observer(self, fn: MutationObserver) -> None:
        """
        Add another observer of changes made through this connection.

        :param fn: An object to call after any transaction with changes is
            committed on this connection.
        """
        self._observers = self._observers + (fn,)

    def iterdump(self) -> Iterator[str]:
        """
        :return: SQL statements which can be used to reconstruct the database
            state.
        """
        return self._conn.iterdump()

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
        """
        If there are recorded mutations, deliver them to each of the observers and
        then forget about them.

        :return: A generator of the return values of the observers.
        """
        if self._mutations:
            to_signal = self._mutations
            self._mutations = list()
            for ob in self._observers:
                yield ob(cursor, to_signal)

    def cursor(self, factory: Optional[type] = None) -> _ReplicationCapableCursor:
        """
        Get a replication-capable cursor for this connection.
        """
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
    _important: bool = field(init=False, default=False)

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        return self._cursor.close()

    def execute(self, statement: str, row: Iterable[SQLType] = ()) -> Cursor:
        """
        sqlite's Cursor API

        :param row: the arguments
        """
        assert isinstance(row, tuple)
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


def statements_to_snapshot(statements: Iterator[str]) -> bytes:
    """
    Take a snapshot of the database reachable via the given connection.

    The snapshot is consistent and write transactions on the given connection
    are blocked until it has been completed.
    """
    return cbor2.dumps({"version": 1, "statements": [x for x in statements]})


def connection_to_statements(connection: Connection) -> Iterator[str]:
    """
    Create an iterator of SQL statements as strings representing a consistent,
    self-contained snapshot of the database reachable via the given
    connection.
    """
    return iter(connection.iterdump())


# Convenience API to dump statements and encode them for storage.
snapshot: Callable[[Connection], bytes] = compose(
    statements_to_snapshot, connection_to_statements
)


async def tahoe_lafs_uploader(
    client: ITahoeClient,
    recovery_cap: str,
    get_snapshot_data: DataProvider,
    entry_name: str,
) -> None:
    """
    Upload a replica to Tahoe, linking the result into the given recovery
    mutable capbility under the name given by :py:data:`SNAPSHOT_NAME`.
    """
    snapshot_immutable_cap = await client.upload(get_snapshot_data)
    await client.link(recovery_cap, entry_name, snapshot_immutable_cap)


def get_tahoe_lafs_direntry_uploader(
    client: ITahoeClient,
    directory_mutable_cap: str,
) -> Callable[[str, DataProvider], Awaitable[None]]:
    """
    Bind a Tahoe client to a mutable directory in a callable that will
    upload some data and link it into the mutable directory under the
    given name.

    :return: A callable that will upload some data as the latest replica
        snapshot. The data isn't given directly, but instead from a
        zero-argument callable itself to facilitate retrying.
    """

    async def upload(entry_name: str, get_data_provider: DataProvider) -> None:
        await tahoe_lafs_uploader(
            client, directory_mutable_cap, get_data_provider, entry_name
        )

    return upload


def get_tahoe_lafs_direntry_pruner(
    client: ITahoeClient,
    directory_mutable_cap: str,
) -> Callable[[Callable[[str], bool]], Awaitable[None]]:
    """
    Bind a Tahoe client to a mutable directory in a callable that will
    unlink some entries. Which entries to unlink are controlled by a predicate.

    :return: A callable that will unlink some entries given a
        predicate. The prediate is given a filename inside the mutable to
        consider.
    """

    async def maybe_unlink(predicate: Callable[[str], bool]) -> None:
        """
        For each child of `directory_mutable_cap` delete it iff the
        predicate returns True for that name
        """
        entries = await client.list_directory(directory_mutable_cap)
        for name in entries.keys():
            if predicate(name):
                await client.unlink(directory_mutable_cap, name)

    return maybe_unlink


def get_tahoe_lafs_direntry_lister(
    client: ITahoeClient, directory_mutable_cap: str
) -> EntryLister:
    """
    Bind a Tahoe client to a mutable directory in a callable that will list
    the entries of that directory.
    """

    async def lister() -> dict[str, DirectoryEntry]:
        entries = await client.list_directory(directory_mutable_cap)
        return {
            name: DirectoryEntry(kind, entry.get("size", 0))
            for name, (kind, entry) in entries.items()
        }

    return lister


def get_tahoe_lafs_direntry_replica(
    client: ITahoeClient, directory_mutable_cap: str
) -> Replica:
    """
    Get an object that can interact with a replica stored in a Tahoe-LAFS
    mutable directory.
    """
    uploader = get_tahoe_lafs_direntry_uploader(client, directory_mutable_cap)
    pruner = get_tahoe_lafs_direntry_pruner(client, directory_mutable_cap)
    lister = get_tahoe_lafs_direntry_lister(client, directory_mutable_cap)
    return Replica(uploader, pruner, lister)


def add_events(
    cursor: _SQLite3Cursor,
    events: Iterable[tuple[str, Sequence[SQLType]]],
    important: bool,
) -> None:
    """
    Add some new changes to the event-log.
    """
    sql_args = []
    for sql, args in events:
        assert all(
            isinstance(a, SQLRuntimeType) for a in args
        ), f"{args} contains non-SQL value"
        sql_args.append((sql, cbor2.dumps(args), important))
    cursor.executemany(
        """
        INSERT INTO [event-stream]([statement], [serialized_arguments], [important])
        VALUES (?, ?, ?)
        """,
        sql_args,
    )


def get_events(conn: _SQLite3Connection) -> EventStream:
    """
    Return all events currently in our event-log.
    """
    with conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT [sequence-number], [statement], [serialized_arguments], [important]
            FROM [event-stream]
            """
        )
        rows = cursor.fetchall()
    return EventStream(
        changes=[
            # List comprehension has incompatible type List[Change]; expected List[_T_co]
            # https://github.com/python-attrs/attrs/issues/519
            Change(seq, stmt, cbor2.loads(arguments), important)  # type: ignore
            for seq, stmt, arguments, important in rows
        ]
    )


def prune_events_to(conn: _SQLite3Connection, sequence_number: int) -> None:
    """
    Remove all events <= sequence_number
    """
    with conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            DELETE FROM [event-stream]
            WHERE [sequence-number] <= (?)
            """,
            (sequence_number,),
        )
        cursor.fetchall()


@frozen
class AccumulatedChanges:
    """
    A summary of some changes that have been made.

    :ivar important: Are any of these "important" changes?

    :ivar size: The approximate size in bytes to represent all of the changes.
    """

    important: bool
    size: int

    @classmethod
    def no_changes(cls) -> AccumulatedChanges:
        """
        Create an ``AccumulatedChanges`` that represents no changes.
        """
        return cls(False, 0)

    @classmethod
    def from_connection(cls, connection: _SQLite3Connection) -> AccumulatedChanges:
        """
        Load information about unreplicated changes from the database.
        """
        # this size is larger than what we would have computed via
        # `from_changes` which only counts the statement-sizes .. but
        # maybe fine? (also could fix by just accumulating the
        # statement-sizes instead below)
        events = get_events(connection)
        data = events.to_bytes()
        size = data.seek(0, os.SEEK_END)
        any_important = any(change.important for change in events.changes)
        return cls(any_important, size)

    @classmethod
    def from_statements(
        cls,
        important: bool,
        statements: Iterable[tuple[str, Sequence[SQLType]]],
    ) -> AccumulatedChanges:
        """
        Load information about unreplicated changes from SQL statements giving
        those changes.
        """
        # note that we're ignoring a certain amount of size overhead here: the
        # _actual_ size will be some CBOR information and the sequence number,
        # although the statement text should still dominate.
        # XXX Fix the size calculation
        return cls(important, sum(len(sql) for (sql, _) in statements))

    def __add__(self, other: AccumulatedChanges) -> AccumulatedChanges:
        return AccumulatedChanges(
            self.important or other.important, self.size + other.size
        )


def event_stream_name(high_seq: int) -> str:
    """
    Construct the basename of the event stream object containing the given
    highest sequence number.
    """
    return f"event-stream-{high_seq}"


@define
class _ReplicationService(Service):
    """
    Perform all activity related to maintaining a remote replica of the local
    ZKAPAuthorizer database.

    If this service is running for a database then the database is in
    replication mode and changes will be uploaded.

    :ivar _connection: A connection to the database being replicated.

    :ivar _replicating: The long-running replication operation.  This is never
        expected to complete but it will be cancelled when the service stops.
    """

    name = "replication-service"  # type: ignore # Service assigns None, screws up type inference
    _logger = Logger()

    _connection: _ReplicationCapableConnection = field()
    _replica: Replica
    _snapshot_policy: SnapshotPolicy
    _replicating: Optional[Deferred] = field(init=False, default=None)

    _changes: AccumulatedChanges = AccumulatedChanges.no_changes()
    _jobs: DeferredQueue = field(factory=DeferredQueue)

    @property
    def _unreplicated_connection(self):
        """
        A normal SQLite3 connection object, changes made via which will not be
        replicated.
        """
        return self._connection._conn

    def startService(self) -> None:
        super().startService()

        # Register ourselves as a change observer (first! we don't want to
        # miss anything) and then put the database into replication mode so
        # that there are recorded events for us to work with.
        self._connection.add_mutation_observer(self.observed_event)
        self._connection.enable_replication()

        # Reflect whatever state is left over in the database from previous
        # efforts.
        self._changes = AccumulatedChanges.from_connection(
            self._unreplicated_connection
        )

        self.queue_job(ReplicationJob.startup)

        # Start the actual work of reacting to changes by uploading them (as
        # appropriate).
        self._replicating = Deferred.fromCoroutine(self._replicate())

    async def _replicate(self) -> None:
        """
        React to changes by replicating them to remote storage.
        """
        try:
            await self.wait_for_uploads()
        except CancelledError:
            # Ignore cancels; this will be the normal way we quit -- see
            # stopService.
            pass
        except Exception:
            # If something besides a cancel happens, at least make it visible.
            self._logger.failure("unexpected wait_for_uploads error")

        return None

    def queue_job(self, job: ReplicationJob) -> None:
        """
        Queue a job, if it is not already queued, to be executed after any other
        queued jobs.
        """
        if job not in self._jobs.pending:
            self._jobs.put(job)

    @log_call(action_type="zkapauthorizer:replicate:queue-event-upload")
    def queue_event_upload(self) -> None:
        """
        Request an event-stream upload of outstanding events.
        """
        self.queue_job(ReplicationJob.event_stream)

    @log_call(action_type="zkapauthorizer:replicate:queue-snapshot-upload")
    def queue_snapshot_upload(self) -> None:
        """
        Request that an upload of a new snapshot occur. Stale
        event-streams will also be pruned after the snapshot is
        successfully uploaded.
        """
        self.queue_job(ReplicationJob.snapshot)

    async def wait_for_uploads(self) -> None:
        """
        An infinite async loop that processes uploads of event-streams or
        snapshots
        """
        while True:
            job = await self._jobs.get()
            if job == ReplicationJob.event_stream:
                await self._do_one_event_upload()
            elif job == ReplicationJob.snapshot:
                await self._do_one_snapshot_upload()
            elif job == ReplicationJob.consider_snapshot:
                await self._do_consider_snapshot()
            elif job == ReplicationJob.startup:
                await self._do_startup()
            else:
                raise Exception("internal error")  # pragma: nocover

    async def _do_startup(self) -> None:
        """
        Check local and remote state to determine if there is any work that should
        be done immediately.

        Currently, this will upload a snapshot if none exists in the replica,
        or upload an event stream if there are events that warrant immediate
        upload.
        """
        if await self.should_upload_snapshot():
            self.queue_snapshot_upload()
        elif self.should_upload_eventstream(self._changes):
            self.queue_event_upload()

    @log_call(action_type="zkapauthorizer:replicate:snapshot-upload")
    async def _do_one_snapshot_upload(self) -> None:
        """
        Perform a single snapshot upload, including pruning event-streams
        from the replica that are no longer relevant.
        """
        # extract sequence-number and snapshot data
        seqnum = 1
        rows = (
            self._connection.cursor()
            .execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'event-stream'", tuple()
            )
            .fetchall()
        )
        if len(rows):
            seqnum = int(rows[0][0])

        snap = snapshot(self._connection)

        # upload snapshot
        await self._replica.upload("snapshot", lambda: BytesIO(snap))

        # remove local event history (that should now be encapsulated
        # by the snapshot we just uploaded)
        prune_events_to(self._connection._conn, seqnum)

        # if we crash here, there will be extra event-stream objects
        # in the replica. This will be fixed correctly upon our next
        # snapshot upload. The extra event-stream objects will be
        # ignored by the recovery code.

        # prune old events from the replica
        def is_old_eventstream(fname: str) -> bool:
            """
            :returns: True if the `fname` is an event-stream object and the
                sequence number is strictly less than our snapshot's
                maximum sequence.
            """
            m = re.match("event-stream-([0-9]*)", fname)
            if m:
                seq = int(m.group(1))
                if seq <= seqnum:
                    return True
            return False

        await self._replica.prune(is_old_eventstream)

    @log_call(action_type="zkapauthorizer:replicate:event-upload")
    async def _do_one_event_upload(self) -> None:
        """
        Process a single upload of all current events and then delete them
        from our database.
        """
        events = get_events(self._unreplicated_connection)

        high_seq = events.highest_sequence()
        # if this is None there are no events at all
        if high_seq is None:
            return

        # otherwise, upload the events we found.
        name = event_stream_name(high_seq)
        await self._replica.upload(name, events.to_bytes)

        # then discard the uploaded events from the local database.
        prune_events_to(self._unreplicated_connection, high_seq)

        # Arrange to examine replica state soon to determine whether taking a
        # new snapshot and pruning existing event streams is useful.
        self.queue_job(ReplicationJob.consider_snapshot)

    async def _do_consider_snapshot(self) -> None:
        """
        Inspect local and remote state to decide if the cost of taking and
        uploading a new snapshot is worth the resulting savings in storage.
        """
        local_size = await self._new_snapshot_size()
        replica_size = await self._replica_size()
        if self._snapshot_policy.should_snapshot(local_size, replica_size):
            self.queue_snapshot_upload()

    async def _new_snapshot_size(self) -> int:
        """
        Measure the size of snapshot of the current database state, in bytes.
        """
        return len(snapshot(self._connection))

    async def _replica_size(self) -> list[int]:
        """
        Retrieve the size of all the files that are part of the current on-grid
        replica.
        """
        entries = await self._replica.entry_lister()
        return [
            entry.size
            for (name, entry) in entries.items()
            if entry.kind == "filenode"
            and name == "snapshot"
            or name.startswith("event-stream-")
        ]

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
        all_changes: Iterable[Mutation],
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
        # A mutation contains one statement and one or more rows of arguments
        # that go with it.  We're going to generate an event per
        # statement/argument pair - so "unroll" those rows and pair each
        # individual argument tuple with its statement.
        events = []
        any_important = False
        for (important, sql, manyargs) in all_changes:
            any_important = any_important or important
            for args in manyargs:
                events.append((sql, args))
        add_events(unobserved_cursor, events, any_important)
        changes = AccumulatedChanges.from_statements(any_important, events)
        self._changes = self._changes + changes
        if self.should_upload_eventstream(self._changes):
            return self._complete_upload
        else:
            return lambda: None

    def _complete_upload(self) -> None:
        """
        This is called after the transaction closes (because we return it
        from our observer function). See
        _ReplicationCapableConnection.__exit__
        """
        self.queue_event_upload()
        self._changes = AccumulatedChanges.no_changes()

    async def should_upload_snapshot(self) -> bool:
        """
        :returns: True if there is no remote snapshot
        """
        entries = await self._replica.list()
        return SNAPSHOT_NAME not in entries

    def should_upload_eventstream(self, changes: AccumulatedChanges) -> bool:
        """
        :returns: True if we have accumulated enough statements to upload
            an event-stream record.
        """
        return changes.important or changes.size >= 570000


def replication_service(
    replicated_connection: _ReplicationCapableConnection,
    replica: Replica,
    snapshot_policy: SnapshotPolicy,
) -> IService:
    """
    Return a service which implements the replication process documented in
    the ``backup-recovery`` design document.
    """
    return _ReplicationService(
        connection=replicated_connection,
        replica=replica,
        snapshot_policy=snapshot_policy,
    )
