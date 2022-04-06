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
from typing import Any, BinaryIO, Callable, ContextManager, Iterable, Iterator, Optional

import cbor2
from attrs import Factory, define, frozen
from compose import compose
from twisted.application.service import IService
from twisted.internet.defer import Deferred, DeferredSemaphore
from twisted.python.filepath import FilePath
from twisted.python.lockfile import FilesystemLock

from .config import REPLICA_RWCAP_BASENAME, Config
from .sql import Connection, Cursor, bind_arguments, statement_mutates
from .tahoe import ITahoeClient, attenuate_writecap


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
    config_lock.lock()
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


@define
class _Important:
    """
    A context-manager to set and unset the ._important flag on a
    _ReplicationCapableConnection
    """

    _replication_conn: _ReplicationCapableConnection

    def __enter__(self):
        self._replication_conn._important = True

    def __exit__(self, *args):
        self._replication_conn._important = False


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
    # true while statements are "important" (which is pased along to
    # the observers and interpreted as being "important data that the
    # user will be interested in preserving")
    _important: bool

    def enable_replication(self) -> None:
        """
        Turn on replication support.
        """
        self._replicating = True

    def iterdump(self) -> Iterable[str]:
        """
        :return: SQL statements which can be used to reconstruct the database
            state.
        """
        return self._conn.iterdump()

    def close(self):
        return self._conn.close()

    def __enter__(self) -> ContextManager:
        return self._conn.__enter__()

    def __exit__(
        self,
        exc_type: Optional[type],
        exc_value: Optional[BaseException],
        exc_tb: Optional[Any],
    ) -> None:
        return self._conn.__exit__(exc_type, exc_value, exc_tb)

    def cursor(self, factory: Optional[type] = None) -> Cursor:
        kwargs = {}
        if factory is not None:
            kwargs["factory"] = factory
        cursor = self._conn.cursor(**kwargs)
        return _ReplicationCapableCursor(cursor)

    def important(self):
        """
        Create a new context-manager that -- while active -- sets the
        'important' flag to true and resets it afterwards.
        """
        return _Important(self)


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
    _observers: list = Factory(list)

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        return self._cursor.close()

    def execute(self, statement, row=None):
        """
        sqlite's Cursor API

        :param row: the arguments
        """
        if row is None:
            args = (statement,)
        else:
            args = (statement, row)
        self._cursor.execute(*args)
        if statement_mutates(statement):
            self._observe_mutations(statement, (row,))

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, n):
        return self._cursor.fetchmany(n)

    def fetchone(self):
        return self._cursor.fetchone()

    def executemany(self, statement, rows):
        self._cursor.executemany(statement, rows)
        if statement_mutates(statement):
            self._observed_mutations(statement, rows)

    def _observed_mutations(self, statement, rows):
        """
        One or more statements that mutate the database have been
        executed. The transaction is still active. Notify observers.
        """
        for ob in self._observers:
            ob(self, self._important, statement, rows)


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

    :return Callable[str, [Callable[[], BinaryIO]], None]: A callable that
        will upload some data as the latest replica snapshot. The data
        isn't given directly, but instead from a zero-argument callable
        itself to facilitate retrying.
    """

    async def upload(
        entry_name: str, get_data_provider: Callable[[], BinaryIO]
    ) -> None:
        await tahoe_lafs_uploader(
            client, directory_mutable_cap, get_data_provider, entry_name
        )

    return upload


class ReplicationService:
    """
    This service uploads event-streams
    """

    _store: None  #: VoucherStore
    _uploader: Callable[[str, BinaryIO], None]
    _connection: _ReplicationCapableConnection
    _accumulated_size: int = 0
    _trigger = DeferredSemaphore(1)

    def startService(self):
        # XXX this will be a bigger number than we had before .. but maybe fine
        self._accumulated_size = len(self._store.get_events().to_bytes())
        # XXX
        # self._accumulated_size = sum(len(change.statement) for change in self._store.get_events().changes)
        if not self.big_enough():
            self._trigger.acquire()
        d = Deferred.fromCoroutine(self.wait_for_uploads())
        d.addErrback(print)

        self._connection.add_mutation_observer(self.observed_event)
        return

    def queue_upload(self):
        if self._trigger.tokens:
            self._trigger.release()
        else:
            # we're already uploading
            pass

    async def wait_for_uploads(self):
        """
        An infinite async loop that proecsses uploads
        """
        while True:
            await self._trigger.acquire()
            try:
                await self._do_one_upload()
            except Exception:
                # probably log the error?
                pass

    async def _do_one_upload(self):
        """
        Process a single upload.
        """
        events = self._store.get_events()
        # upload latest event-stream
        await self._uploader(
            "event-stream-{}".format(events.higest_sequence()),
            events.to_bytes,
        )
        # prune the database
        self._store.prune_events_to(events.higest_sequence())

    def observed_event(self, cursor, important, statement, args):
        """
        A mutating SQL statement was observed by the cursor
        """
        bound_statement = bind_arguments(cursor, statement, args)
        self._store.add_event.wrapped(cursor, bound_statement)
        # note that we're ignoring a certain amount of size overhead
        # here: the _actual_ size will be some CBOR information and
        # the sequence number, although the statement text should
        # still dominate.
        self._accumulated_size += len(bound_statement)
        if important or self.big_enough():
            self.queue_upload()
            self._accumulated_size = 0

    def big_enough(self):
        return self._accumulated_size >= 570000


def replication_service(connection) -> IService:
    """
    Return a service which implements the replication process documented in
    the ``backup-recovery`` design document.
    """
    return ReplicationService(connection=connection)
