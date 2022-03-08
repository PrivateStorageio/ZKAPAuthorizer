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
from typing import Iterator

from attrs import define, field
from compose import compose
from twisted.application.service import Service
from twisted.python.filepath import FilePath
from twisted.python.lockfile import FilesystemLock

from .config import REPLICA_RWCAP_BASENAME, Config
from .tahoe import Tahoe, attenuate_writecap, get_tahoe_client


class ReplicationAlreadySetup(Exception):
    """
    An attempt was made to setup of replication but it is already set up.
    """


def replication_service(reactor, node, store):
    """
    Return a service which implements the replication process documented in
    the ``backup-recovery`` design document:
    """
    return _ReplicationService(reactor, node.config.store)


SERVICE_NAME = "replication-service"


@define
class _ReplicationService(Service):
    name = SERVICE_NAME

    _reactor = field()
    _config: Config
    _store: "VoucherStore"

    _tahoe: Tahoe = field()
    _replica_dircap: str = field()

    @_tahoe.default
    def _tahoe_default(self):
        return get_tahoe_client(self._reactor, self._config)

    @_replica_dircap.default
    def _replica_dircap_default(self):
        return self._tahoe.get_private_path(REPLICA_RWCAP_BASENAME)

    def startService(self):
        # 1. Put the store into replication mode.
        # 2. If necessary, create and upload a snapshot.

        upload_snapshot(self._replica_dircap, self._tahoe, self._store)
        # 3. As necessary, upload the event stream.
        # 4. Repeat 2-3 as beneficial for total committed storage.
        self._store.observe_event_stream(self._event_stream_observer)

    def _event_stream_observer(self, event_stream_size):
        if event_stream_size > 570000:
            upload_event_stream(self._replica_dircap, self._tahoe, self._store)


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
    replica_dircap: str, tahoe: Tahoe, store: "VoucherStore"
) -> Awaitable[None]:
    path = await write_snapshot(store.event_stream())
    entry_cap = await tahoe.upload(path)
    await tahoe.link(replica_dircap, "event-stream-XXXX", entry_cap)


async def upload_snapshot(replica_dircap, tahoe, store):
    """
    Create a database snapshot and store it on a Tahoe-LAFS grid.
    """
    path = await write_snapshot(store.snapshot())
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


# XXX circular
from .model import VoucherStore
