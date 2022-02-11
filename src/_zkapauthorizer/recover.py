__all__ = [
    "RecoveryState",
    "IRecoverer",
    "canned_recoverer",
    "success_recoverer",
]

from collections.abc import Awaitable
from enum import Enum, auto
from sqlite3 import Cursor
from typing import Callable, List, Optional, TextIO

from allmydata.node import _Config
from attrs import define
from hyperlink import DecodedURL
from treq.client import HTTPClient
from twisted.python.filepath import FilePath
from zope.interface import Interface, implementer

from .tahoe import download


class AlreadyRecovering(Exception):
    """
    A recovery attempt is already in-progress so another one cannot be made.
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
    failed = auto()


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


class IStatefulRecoverer(Interface):
    """
    An object which can recover ZKAPAuthorizer state from a replica and report
    on the status of this recovery.
    """

    def recover(cap: str, cursor: Cursor) -> None:
        """
        Begin the recovery process using the given database cursor.

        :param cap: The Tahoe-LAFS read-capability which can be used to
            retrieve the replica.

        :param cursor: A database cursor which can be used to populate the
            database with recovered state.

        :raise AlreadyRecovering: If recovery has already been attempted
            (successfully or otherwise).
        """

    def state() -> RecoveryState:
        """
        Get the current state of the recovery attempt.
        """


SetState = Callable[[RecoveryState], None]


class ISynchronousRecoverer(Interface):
    """
    An object which can recover ZKAPAuthorizer state from a replica.
    """

    def recover(set_state: SetState, cap: str, cursor: Cursor) -> Awaitable:
        """
        Begin the recovery process into the given store.

        :param set_state: A callable which can be used to report on recovery
            progress.

        :param cap: See ``IStatefulRecoverer.recover``

        :param cursor: See ``IStatefulRecoverer.recover``
        """


class IRecoverer(Interface):
    """
    Like ``ISynchronousRecoverer`` but expected to operate asynchronously.
    """

    def recover(set_state: SetState, cap: str, cursor: Cursor) -> Awaitable:
        """
        Like ``ISynchronousRecoverer.recover`` but asynchronous.
        """


@implementer(IStatefulRecoverer)
@define
class StatefulRecoverer:
    """
    An ``IRecoverer`` that exposes changing state as it progresses through the
    recovery process.
    """

    _recoverer: IRecoverer
    _state: RecoveryState = RecoveryState(stage=RecoveryStages.inactive)

    async def recover(self, cap, cursor):
        if self._state.stage != RecoveryStages.inactive:
            raise AlreadyRecovering()

        self._set_state(RecoveryState(stage=RecoveryStages.started))
        try:
            await self._recoverer.recover(self._set_state, cap, cursor)
        except Exception as e:
            self._set_state(
                RecoveryState(stage=RecoveryStages.failed, failure_reason=str(e))
            )
        else:
            self._set_state(RecoveryState(stage=RecoveryStages.succeeded))

    def _set_state(self, state):
        self._state = state

    def state(self):
        return self._state


@implementer(IRecoverer)
@define
class NullRecoverer:
    """
    An ``IRecoverer`` that does nothing.
    """

    async def recover(self, set_state, cap, cursor):
        pass


@implementer(IRecoverer)
@define
class BrokenRecoverer:
    """
    An ``IRecoverer`` with a ``recover`` method that raises exceptions.
    """

    async def recover(self, set_state, cap, cursor):
        raise Exception("BrokenRecoverer does what it says.")


def canned_recoverer(state):
    """
    An ``IStatefulRecoverer`` that always immediately claims whatever you tell
    it to (without actually doing anything).
    """
    return StatefulRecoverer(
        NullRecoverer(),
        state,
    )


def fail_recoverer():
    """
    An ``IRecoverer`` that always immediately claims to have failed (without
    actually doing anything).
    """
    return canned_recoverer(
        RecoveryState(
            stage=RecoveryStages.failed,
            failure_reason="no real recoverer configured",
        ),
    )


def success_recoverer():
    """
    An ``IRecoverer`` that always immediately claims to have succeeded
    (without actually doing anything).
    """
    return canned_recoverer(
        RecoveryState(stage=RecoveryStages.succeeded),
    )


@implementer(ISynchronousRecoverer)
@define
class MemorySnapshotRecoverer:
    """
    An ``IRecoverer`` that synchronously loads a snapshot from a list of
    Python strings into the database.
    """

    _statements: List[str]

    def recover(self, set_state, cap, cursor):
        """
        Synchronously execute our statement list against the given cursor.
        """
        for sql in self._statements:
            cursor.execute(sql)
        set_state(RecoveryState(stage=RecoveryStages.succeeded))


@implementer(ISynchronousRecoverer)
@define
class SynchronousStorageSnapshotRecoverer:
    """
    An ``IRecoverer`` that synchronously loads a snapshot from the local
    synchronous storage into the database.
    """

    _open: Callable[[str], TextIO]

    def recover(self, set_state, cap, cursor):
        """
        Synchronously execute statements read from the snapshot path against the
        given cursor.
        """
        with self._open(cap) as f:
            statements = list(f)
        MemorySnapshotRecoverer(statements).recover(set_state, cap, cursor)


@implementer(IRecoverer)
@define(frozen=True)
class TahoeLAFSRecoverer:
    """
    An ``IRecoverer`` that downloads an object identified by a Tahoe-LAFS
    capability and recovers the state by synchronously (TODO: asynchronous)
    importing the data it contains.
    """

    _treq: HTTPClient
    _node_config: _Config
    _download: Callable[[HTTPClient, FilePath, DecodedURL, str], Awaitable] = download

    @property
    def _api_root(self):
        return self._node_config.get_config_path("node.url")

    @property
    def _snapshot_path(self):
        return FilePath(self._node_config.get_private_path("snapshot.sql"))

    async def recover(self, set_state, cap, cursor):
        """
        Download data for the given capability into the node's private directory.
        Then load it into a database using the given cursor.
        """
        set_state(RecoveryState(stage=RecoveryStages.downloading))
        await self._download(self._treq, self._snapshot_path, self._api_root, cap)

        set_state(RecoveryState(stage=RecoveryStages.importing))

        def opener(cap):
            return open(self._snapshot_path.path, "rt")

        sync_recoverer = SynchronousStorageSnapshotRecoverer(opener)
        sync_recoverer.recover(set_state, cap, cursor)
