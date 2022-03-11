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

from collections.abc import Awaitable, Callable
from sqlite3 import Connection, Cursor
from typing import Iterator, Union

from attrs import define, field
from compose import compose
from sqlparse import parse
from sqlparse.sql import Token
from sqlparse.tokens import Name
from twisted.application.service import Service
from twisted.internet.defer import CancelledError, Deferred
from twisted.python.filepath import FilePath
from twisted.python.lockfile import FilesystemLock

from .config import REPLICA_RWCAP_BASENAME, Config, _Config
from .tahoe import CapStr, Tahoe, attenuate_writecap, get_tahoe_client


class ReplicationAlreadySetup(Exception):
    """
    An attempt was made to setup of replication but it is already set up.
    """


SQLType = Union[int, float, str, bytes, None]


@define
class Change:
    """
    Represent an item in a replication event stream as a SQL statement string
    and its arguments.
    """

    statement: str
    arguments: tuple[SQLType, ...]


EventStream = list[Change]


def event_stream_to_bytes(event_stream):
    return b""


def replication_service(reactor, node, store):
    """
    Return a service which implements the replication process documented in
    the ``backup-recovery`` design document:
    """
    return _ReplicationService(reactor, node.config, store)


SERVICE_NAME = "replication-service"


@define
class _ReplicationService(Service):
    """
    Perform all activity related to maintaining a remote replica of the local
    ZKAPAuthorizer database.

    :ivar _reactor: The reactor to use for this activity.

    :ivar _config: The Tahoe-LAFS configuration for the node this service runs
        in.

    :ivar _tahoe: A Tahoe-LAFS client to perform upload/download operations
        for replica maintenance.

    :ivar _replica_dircap: A Tahoe-LAFS read-write directory capability
    """

    name = SERVICE_NAME

    _reactor = field()
    _config: Config
    _tahoe: Tahoe = field()
    _replica_dircap: str = field()
    _conn: "ReplicationCapableConnection" = field()

    _replicating: Deferred = field(init=False, default=None)

    def startService(self):
        # Tell the store to initiate replication when appropriate.
        self._replicating = self._conn.run_replication(
            lambda conn, replica_dircap: replicate(
                self._reactor,
                get_tahoe_client(self._reactor, self._config),
                conn,
                replica_dircap,
            ),
        )

    def stopService(self):
        replicating = self._replicating
        self._replicating = None

        def catch_cancelled(err):
            err.trap(CancelledError)
            return None

        replicating.addErrback(catch_cancelled)
        replicating.cancel()
        return replicating


async def replicate(
    reactor,
    tahoe: Tahoe,
    conn: ReplicationCapableConnection,
    replica_dircap: CapStr,
) -> Awaitable[None]:
    # 1. If there is no up to date snapshot
    if await snapshot_needed(replica_dircap, tahoe):
        # then create and upload one.
        await upload_snapshot(replica_dircap, tahoe, conn)

    # 2. As necessary, upload the event stream.
    conn.observe_event_stream(
        # XXX this callback should be run in a transaction?
        lambda conn, event_stream: event_stream_observer(
            replica_dircap,
            tahoe,
            conn,
            event_stream,
        ),
    )


async def snapshot_needed(replica_dircap, tahoe) -> Awaitable[bool]:
    """
    Determine whether the remote replica is in need of a new snapshot.
    """
    entries = await tahoe.list_directory(replica_dircap)
    return "snapshot" not in entries


async def event_stream_observer(replica_dircap, tahoe, event_stream):
    """
    Observe changes to the database event stream and upload them when they are
    large or urgent.
    """
    # XXX fix hard-coded 570000
    if event_stream.urgent or event_stream.size > 570000:
        await upload_event_stream(replica_dircap, tahoe, event_stream)
        event_stream.mark_uploaded()


async def fail_setup_replication():
    """
    A replication setup function that always fails.
    """
    raise Exception("Test not set up for replication")


async def setup_tahoe_lafs_replication(client: Tahoe) -> Awaitable[str]:
    """
    Configure the ZKAPAuthorizer plugin that lives in the Tahoe-LAFS node with
    the given configuration to replicate its state onto Tahoe-LAFS storage
    servers using that Tahoe-LAFS node.
    """
    # Find the configuration path for this node's replica.
    config_path = client.get_private_path(REPLICA_RWCAP_BASENAME)

    # Take an advisory lock on the configuration path to avoid concurrency
    # shennanigans.
    config_lock = FilesystemLock(config_path.path + ".lock")

    #### XXX this needs to return True
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


def with_replication(connection: Connection):
    """
    Wrap a replicating support layer around the given connection.
    """
    return _ReplicationCapableConnection(connection)


@define
class _ReplicationCapableConnection:
    """
    Wrap a ``sqlite3.Connection`` to provide additional snapshot- and
    streaming replication-related features.

    All of this type's methods are intended to behave the same way as
    ``sqlite3.Connection``\ 's methods except they may also add some
    additional functionality to support replication.
    """

    _conn: Connection

    def snapshot(self) -> bytes:
        """
        Create and return a byte string representing a consistent, self-contained
        snapshot of the wrapped database.
        """
        return snapshot(self._conn)

    def close(self):
        return self._conn.close()

    def __enter__(self):
        return self._conn.__enter__()

    def __exit__(self, *args):
        return self._conn.__exit__(*args)

    def cursor(self):
        return _ReplicationCapableCursor(self._conn.cursor())


@define
class _ReplicationCapableCursor:
    """
    Wrap a ``sqlite3.Cursor`` to provide additional streaming
    replication-related features.

    All of this type's attributes and methods are intended to behave the same
    way as ``sqlite3.Cursor``\ 's methods except they may also add some
    additional functionality to support replication.
    """

    _cursor: Cursor

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        return self._cursor.close()

    def execute(self, statement, row=None):
        if row is None:
            args = (statement,)
        else:
            args = (statement, row)
        self._cursor.execute(*args)

    def fetchall(self):
        return self._cursor.fetchall()

    def fetchmany(self, n):
        return self._cursor.fetchmany(n)

    def fetchone(self):
        return self._cursor.fetchone()

    def executemany(self, statement, rows):
        self._cursor.executemany(statement, rows)


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
    return connection.iterdump()


# Convenience API for dump statements, netstring-encoding them, and
# concatenating them all into a single byte string.
snapshot: Callable[[Connection], bytes] = compose(
    b"".join, statements_to_snapshot, connection_to_statements
)


async def write_snapshot(
    get_private_path: Callable[[str], FilePath], statements: list[str]
) -> FilePath:
    path = get_private_path("temp")
    with open(path.path, "wt") as f:
        f.writelines(statements)
    return path


async def upload_event_stream(
    replica_dircap: str,
    tahoe: Tahoe,
    event_stream: EventStream,
) -> Awaitable[None]:
    """
    Upload one
    """
    path = await write_snapshot(event_stream_to_bytes(event_stream))
    entry_cap = await tahoe.upload(path)
    await tahoe.link(
        replica_dircap, f"event-stream-{event_stream.sequence_number}", entry_cap
    )


async def upload_snapshot(
    replica_dircap: CapStr, tahoe: Tahoe, conn: ReplicationCapableConnection
) -> Awaitable[None]:
    """
    Create a database snapshot and store it on a Tahoe-LAFS grid.
    """
    path = await write_snapshot(snapshot(conn))
    entry_cap = await tahoe.upload(path)
    await tahoe.link(replica_dircap, "snapshot", entry_cap)


@define
class Snapshot:
    """
    Represent a database snapshot.

    :ivar name: The name of this snapshot in the replica directory.
    :ivar size: The unencoded stored size of this snapshot.
    :ivar ro_cap: A read-only capability to the snapshot.
    """

    name: str
    size: int
    ro_cap: str


@define
class ReplicaState:
    snapshots: list[Snapshot]


async def read_replica_state(replica_dircap, tahoe) -> Awaitable[ReplicaState]:
    snapshots = []
    children = await tahoe.list_directory(replica_dircap)
    for name, child in children.items():
        if name.startswith("snapshot-"):
            snapshots.append(Snapshot(name, child["size"], child["ro_uri"]))
    return ReplicaState(snapshots)


def statement_mutates(statement):
    (statement,) = parse(statement)
    return statement.tokens[0].normalized not in {"SELECT"}


def record(conn, statement, row):
    recordmany(conn, statement, [row])


def event_stream_statement(conn, statement, row):
    pass


def recordmany(conn, statement, rows):
    for row in rows:
        sql = event_stream_statement(conn, statement, row)
        conn.execute("INSERT INTO [event-stream] VALUES (?)", (sql,))
