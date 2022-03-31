"""
A system for recovering local ZKAPAuthorizer state from a remote replica.
"""

__all__ = [
    "RecoveryStages",
    "RecoveryState",
    "SetState",
    "Downloader",
    "StatefulRecoverer",
    "make_fail_downloader",
    "noop_downloader",
]

from collections.abc import Awaitable
from enum import Enum, auto
from io import BytesIO
from sqlite3 import Cursor
from typing import BinaryIO, Callable, Iterator, Optional

from attrs import define
from twisted.python.filepath import FilePath

from .sql import escape_identifier
from .tahoe import Tahoe


class SnapshotMissing(Exception):
    """
    No snapshot was not found in the replica directory.
    """


class RecoveryStages(Enum):
    """
    Constants representing the different stages a recovery process may have
    reached.

    :ivar inactive: The recovery system has not been activated.  No recovery
        has yet been attempted.

    :ivar succeeded: The recovery system has successfully recovered state from
        a replica.  Recovery is finished.  Since state now exists in the local
        database, the recovery system cannot be re-activated.

    :ivar failed: The recovery system has definitively failed in its attempt
        to recover from a replica.  Recovery will progress no further.  It is
        undefined what state now exists in the local database.
    """

    inactive = auto()
    started = auto()
    downloading = auto()
    importing = auto()
    succeeded = auto()

    download_failed = auto()
    import_failed = auto()


@define(frozen=True)
class RecoveryState:
    """
    Describe the state of an attempt at recovery.

    :ivar state: The recovery process progresses through different stages.
        This indicates the point which that progress has reached.

    :ivar failure_reason: If the recovery failed then a human-meaningful
        (maybe) string giving details about why.
    """

    stage: RecoveryStages = RecoveryStages.inactive
    failure_reason: Optional[str] = None

    def marshal(self) -> dict[str, Optional[str]]:
        return {"stage": self.stage.name, "failure-reason": self.failure_reason}


# A function for reporting a change in the state of a recovery attempt.
SetState = Callable[[RecoveryState], None]

# An object which can retrieve remote ZKAPAuthorizer state.
Downloader = Callable[[SetState], Awaitable[BinaryIO]]

# function which can set remote ZKAPAuthorizer state.
Uploader = Callable[[SetState], Awaitable[None]]


@define
class StatefulRecoverer:
    """
    An ``IRecoverer`` that exposes changing state as it progresses through the
    recovery process.
    """

    _state: RecoveryState = RecoveryState(stage=RecoveryStages.inactive)

    async def recover(
        self,
        download: Downloader,
        cursor: Cursor,
    ) -> Awaitable[None]:
        """
        Begin the recovery process.

        :param downloader: A callable which can be used to retrieve a replica.

        :param cursor: A database cursor which can be used to populate the
            database with recovered state.
        """
        if self._state.stage != RecoveryStages.inactive:
            return

        self._set_state(RecoveryState(stage=RecoveryStages.started))
        try:
            downloaded_data = await download(self._set_state)
        except Exception as e:
            self._set_state(
                RecoveryState(
                    stage=RecoveryStages.download_failed, failure_reason=str(e)
                )
            )
            return

        try:
            recover(statements_from_snapshot(downloaded_data), cursor)
        except Exception as e:
            self._set_state(
                RecoveryState(stage=RecoveryStages.import_failed, failure_reason=str(e))
            )
            return

        self._set_state(RecoveryState(stage=RecoveryStages.succeeded))

    def _set_state(self, state: RecoveryState) -> None:
        """
        Change the recovery state.
        """
        self._state = state

    def state(self) -> RecoveryState:
        """
        Get the latest recovery state.
        """
        return self._state


def make_fail_downloader(reason: Exception) -> Downloader:
    """
    Make a downloader that always fails with the given exception.
    """

    async def fail_downloader(set_state: SetState) -> Awaitable[BinaryIO]:
        raise reason

    return fail_downloader


def make_canned_downloader(data: bytes) -> Downloader:
    """
    Make a downloader that always immediately succeeds with the given value.
    """
    assert isinstance(data, bytes)

    async def canned_downloader(set_state: SetState) -> Awaitable[BinaryIO]:
        return BytesIO(data)

    return canned_downloader


# A downloader that does nothing and then succeeds with an empty string.
noop_downloader = make_canned_downloader(b"")


def statements_from_snapshot(data: BinaryIO) -> Iterator[str]:
    """
    Read the SQL statements which constitute the replica from a byte string.

    :see: http://cr.yp.to/proto/netstrings.txt
    """
    s = data.read()
    pos = 0
    while pos < len(s):
        delim = s.index(b":", pos)
        length = int(s[pos:delim])
        new_pos = delim + 1 + length
        statement = s[delim + 1 : new_pos]
        yield statement.decode("utf-8")
        pos = new_pos + 1


def snapshot(connection: Connection) -> Iterator[str]:
    return connection.iterdump()


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
    """
    for statement in statements:
        # Use netstrings to frame each statement.  Statements can have
        # embedded newlines (and CREATE TABLE statements especially tend to).
        yield netstring(statement.encode("utf-8"))


def recover(statements: Iterator[str], cursor: Cursor) -> None:
    """
    Synchronously execute our statement list against the given cursor.
    """
    # Discard all existing data in the database.
    cursor.execute("SELECT [name] FROM [sqlite_master] WHERE [type] = 'table'")
    tables = cursor.fetchall()
    for (table_name,) in tables:
        cursor.execute(f"DROP TABLE {escape_identifier(table_name)}")

    # The order of statements does not necessarily guarantee that foreign key
    # constraints are satisfied after every statement.  Turn off enforcement
    # so we can insert our rows.  If foreign keys were valid at the dump the
    # snapshot was created then they'll be valid by the time we finish
    # processing all of the statements.  With this pragma, SQLite3 will
    # enforce them when the current transaction is committed and the effect
    # vanishes after the current transaction (whether it commits or rolls
    # back).
    cursor.execute("PRAGMA defer_foreign_keys = ON")

    # Load everything back in two passes.  The two passes thing sucks.
    # However, if a row is inserted into a table and the table has a foreign
    # key constraint and the table it references hasn't been created yet,
    # SQLite3 raises an OperationalError - despite the defer_foreign_keys
    # pragma above.
    #
    # Probably a right-er solution is to change the snapshotter to emit all of
    # the Data Definition Language (DDL) statements first and all of the Data
    # Manipulation Language (DML) statements second so that executing the
    # statements in the order given is correct.
    #
    # Possibly it is also true that if we had never turned on the foreign_keys
    # pragma in the first place, SQLite3 would allow this to pass.  It is too
    # late to turn it off here, though, since it cannot be changed inside a
    # transaction.

    # So, pull the DDL apart from the DML.  Do this in one pass in case
    # iterating statements is destructive.
    dml = []
    for sql in statements:
        if sql.startswith("CREATE TABLE"):
            cursor.execute(sql)
        elif sql not in ("BEGIN TRANSACTION;", "COMMIT;"):
            dml.append(sql)

    # Run all the DML
    for sql in dml:
        cursor.execute(sql)


async def tahoe_lafs_downloader(
    client: Tahoe,
    recovery_cap: str,
    set_state: SetState,
) -> Awaitable[FilePath]:
    """
    Download replica data from the given replica directory capability into the
    node's private directory.
    """
    snapshot_path = client.get_private_path("snapshot.sql")

    set_state(RecoveryState(stage=RecoveryStages.downloading))
    await client.download(snapshot_path, recovery_cap, ["snapshot.sql"])
    return snapshot_path


def get_tahoe_lafs_downloader(client: Tahoe) -> Callable[[str], Downloader]:
    """
    Bind some parameters to ``tahoe_lafs_downloader`` in a convenient way.

    :return: A callable that accepts a Tahoe-LAFS capability string and
        returns a downloader for that capability.
    """

    def get_downloader(cap_str):
        def downloader(set_state):
            return tahoe_lafs_downloader(client, cap_str, set_state)

        return downloader

    return get_downloader
