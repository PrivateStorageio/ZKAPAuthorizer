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

from io import BytesIO
from sqlite3 import Connection, Cursor
from typing import BinaryIO, Callable, Iterator, Optional

import cbor2
from attrs import define, frozen
from compose import compose
from twisted.python.lockfile import FilesystemLock

from .config import REPLICA_RWCAP_BASENAME
from .tahoe import Tahoe, attenuate_writecap


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

    changes: tuple[Change]

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


async def setup_tahoe_lafs_replication(client: Tahoe) -> str:
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


# Convenience API to dump statements, netstring-encoding them, and
# concatenating them all into a single byte string.
snapshot: Callable[[Connection], bytes] = compose(
    b"".join, statements_to_snapshot, connection_to_statements
)


async def tahoe_lafs_uploader(
    client: Tahoe,
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
    client: Tahoe,
    directory_mutable_cap: str,
    entry_name: str = "snapshot.sql",
):
    """
    Bind a Tahoe client to a mutable directory in a callable that will
    upload some data and link it into the mutable directory under the
    given name.

    :return Callable[[Callable[[], BinaryIO]], None]: A callable that
        will upload some data as the latest replica snapshot. The data
        isn't given directly, but instead from a zero-argument callable
        itself to facilitate retrying.
    """

    async def upload(get_data_provider: Callable[[], BinaryIO]) -> None:
        await tahoe_lafs_uploader(
            client, directory_mutable_cap, get_data_provider, entry_name
        )

    return upload
