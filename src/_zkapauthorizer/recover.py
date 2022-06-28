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
from functools import partial
from io import BytesIO
from typing import Callable, Iterable, Iterator, NoReturn, Optional, Sequence

import cbor2
from attrs import define, field

from .replicate import SNAPSHOT_NAME, EventStream, statements_to_snapshot
from .sql import Cursor, escape_identifier
from .tahoe import CapStr, DataProvider, ITahoeClient


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
    inspect_replica = auto()
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

Replica = tuple[
    # The snapshot
    DataProvider,
    # All of the event streams that could possibly -- but do not necessarily
    # -- apply on top of the snapshot.  In normal operation it is likely that
    # they will all apply on top of it but no metadata has been checked yet to
    # verify this.
    Sequence[DataProvider],
]

# An object which can retrieve remote ZKAPAuthorizer state.
Downloader = Callable[[SetState], Awaitable[Replica]]


@define
class StatefulRecoverer:
    """
    An ``IRecoverer`` that exposes changing state as it progresses through the
    recovery process.
    """

    _state: RecoveryState = RecoveryState(stage=RecoveryStages.inactive)
    _listeners: Iterable[Callable[[RecoveryState], object]] = field(default=())

    async def recover(
        self,
        download: Downloader,
        cursor: Cursor,
    ) -> None:
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
            (snapshot, event_streams) = await download(self._set_state)
        except Exception as e:
            self._set_state(
                RecoveryState(
                    stage=RecoveryStages.download_failed, failure_reason=str(e)
                )
            )
            return

        try:
            recover(snapshot, event_streams, cursor)
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
        for listener in self._listeners:
            listener(state)

    def state(self) -> RecoveryState:
        """
        Get the latest recovery state.
        """
        return self._state


def make_fail_downloader(reason: Exception) -> Downloader:
    """
    Make a downloader that always fails with the given exception.
    """

    async def fail_downloader(set_state: SetState) -> NoReturn:
        raise reason

    return fail_downloader


def make_canned_downloader(snapshot: bytes, event_streams: list[bytes]) -> Downloader:
    """
    Make a downloader that always immediately succeeds with the given values.
    """
    assert isinstance(snapshot, bytes)
    assert all(isinstance(e, bytes) for e in event_streams)

    async def canned_downloader(set_state: SetState) -> Replica:
        return (
            partial(BytesIO, snapshot),
            [partial(BytesIO, e) for e in event_streams],
        )

    return canned_downloader


# A downloader that does nothing and then succeeds with an empty snapshot.
noop_downloader = make_canned_downloader(
    statements_to_snapshot(iter([])),
    [],
)


def statements_from_snapshot(get_snapshot: DataProvider) -> Iterator[str]:
    """
    Read the SQL statements which constitute the replica from a byte string.
    """
    with get_snapshot() as fp:
        snapshot = cbor2.load(fp)
    version = snapshot.get("version", None)
    if version != 1:
        raise ValueError(f"Unknown serialized snapshot version {version}")
    return snapshot["statements"]


def recover(
    snapshot: DataProvider, event_stream_data: Sequence[DataProvider], cursor: Cursor
) -> None:
    """
    Synchronously execute statements from a snapshot and any applicable event
    streams against the given cursor.
    """
    recover_snapshot(statements_from_snapshot(snapshot), cursor)
    for event_stream in sorted_event_streams(load_event_streams(event_stream_data)):
        recover_event_stream(event_stream, cursor)


def sorted_event_streams(event_streams: Iterable[EventStream]) -> list[EventStream]:
    """
    Sort some event streams by order of increasing highest change sequence
    number they contain.
    """
    streams_with_changes = (e for e in event_streams if len(e.changes) > 0)

    def event_stream_key(e: EventStream) -> int:
        seq = e.highest_sequence()
        assert seq is not None
        return seq

    return sorted(streams_with_changes, key=event_stream_key)


def load_event_streams(
    event_stream_data: Iterable[DataProvider],
) -> Iterable[EventStream]:
    """
    Load some number of ``EventStream`` instances from their serialized form.
    """
    for event_stream_datum in event_stream_data:
        with event_stream_datum() as f:
            yield EventStream.from_bytes(f)


def recover_event_stream(event_stream: EventStream, cursor: Cursor) -> None:
    """
    Replay the changes in an event stream using the given cursor.
    """
    for change in event_stream.changes:
        if change.statement not in ("BEGIN TRANSACTION;", "COMMIT;"):
            cursor.execute(change.statement, change.arguments)


def recover_snapshot(statements: Iterator[str], cursor: Cursor) -> None:
    """
    Replay the changes in a snapshot using the given cursor.
    """
    # There are certain tables that can't be dropped .. however, we
    # should be refusing to run "recover" at all if there's useful
    # information in the database so these tables should be in the
    # same state as they would be if we'd been able to drop it. This
    # table exists because we use AUTOINCREMENT in the schema.
    do_not_drop = ("sqlite_sequence",)

    # Discard all existing data in the database.
    cursor.execute("SELECT [name] FROM [sqlite_master] WHERE [type] = 'table'", ())
    tables = cursor.fetchall()
    for (table_name,) in tables:
        if table_name in do_not_drop:
            continue
        cursor.execute(f"DROP TABLE {escape_identifier(table_name)}", ())

    # The order of statements does not necessarily guarantee that foreign key
    # constraints are satisfied after every statement.  Turn off enforcement
    # so we can insert our rows.  If foreign keys were valid at the dump the
    # snapshot was created then they'll be valid by the time we finish
    # processing all of the statements.  With this pragma, SQLite3 will
    # enforce them when the current transaction is committed and the effect
    # vanishes after the current transaction (whether it commits or rolls
    # back).
    cursor.execute("PRAGMA defer_foreign_keys = ON", ())

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

    # So, pull the DDL apart from the DML.  Do this in one pass because we
    # won't be able to iterate statements twice.
    dml = []
    for sql in statements:
        if sql.startswith("CREATE TABLE"):
            cursor.execute(sql, ())
        elif sql not in ("BEGIN TRANSACTION;", "COMMIT;"):
            dml.append(sql)

    # Run all the DML
    for sql in dml:
        cursor.execute(sql, ())


async def tahoe_lafs_downloader(
    client: ITahoeClient,
    recovery_cap: str,
    set_state: SetState,
) -> Replica:
    """
    Download replica data from the given replica directory capability into the
    node's private directory.
    """
    set_state(RecoveryState(stage=RecoveryStages.inspect_replica))
    entries = await client.list_directory(recovery_cap)

    set_state(RecoveryState(stage=RecoveryStages.downloading))
    snapshot_path = client.get_private_path(SNAPSHOT_NAME)
    await client.download(snapshot_path, recovery_cap, [SNAPSHOT_NAME])

    entry_paths = []
    for name, (entry_type, entry) in entries.items():
        if entry_type == "filenode" and name.startswith("event-stream-"):
            entry_path = client.get_private_path(name)
            entry_paths.append(entry_path)
            await client.download(entry_path, entry["ro_uri"], None)

    return (
        partial(snapshot_path.open, "rb"),
        [partial(stream_path.open, "rb") for stream_path in entry_paths],
    )


def get_tahoe_lafs_downloader(client: ITahoeClient) -> Callable[[str], Downloader]:
    """
    Bind some parameters to ``tahoe_lafs_downloader`` in a convenient way.

    :return: A callable that accepts a Tahoe-LAFS capability string and
        returns a downloader for that capability.
    """

    def get_downloader(cap_str: CapStr) -> Downloader:
        async def downloader(set_state: SetState) -> Replica:
            return await tahoe_lafs_downloader(client, cap_str, set_state)

        return downloader

    return get_downloader
