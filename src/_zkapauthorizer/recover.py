__all__ = [
    "RecoveryState",
    "IRecoverer",
    "canned_recoverer",
    "success_recoverer",
]

from enum import Enum, auto
from sqlite3 import Cursor
from typing import Callable, List, Optional

from allmydata.node import _Config
from attrs import define
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


class IRecoverer(Interface):
    """
    An object which can recover ZKAPAuthorizer state from a replica.
    """

    def recover(set_state: SetState, cap: str, cursor: Cursor) -> None:
        """
        Begin the recovery process into the given store.

        :param set_state: A callable which can be used to report on recovery
            progress.

        :param cap: See ``IStatefulRecoverer.recover``

        :param cursor: See ``IStatefulRecoverer.recover``
        """


class ILocalRecoverer(Interface):
    """
    An object which can recover ZKAPAuthorizer state from some internal state
    it holds.
    """

    def recover(set_state: SetState, cursor: Cursor) -> None:
        pass


@implementer(IRecoverer)
@define(frozen=True)
class TahoeLAFSCapRecoverer:
    """
    An ``IRecoverer`` that downloads an object identified by a Tahoe-LAFS
    capability and recovers the state by synchronously (TODO: asynchronous)
    importing the data it contains.
    """

    _treq: HTTPClient
    _node_config: _Config

    def recover(self, set_state, cap, cursor):
        api_root = self._node_config.get_config_path("node.url")
        snapshot_path = self._node_config.get_private_path("snapshot.sql")

        async def download_and_recover():
            try:
                set_state(RecoveryState(stage=RecoveryStages.downloading))
                await download(self._treq, snapshot_path, api_root, cap)
                set_state(RecoveryState(stage=RecoveryStages.importing))
                LocalSnapshotRecoverer(snapshot_path).recover(cursor)
                set_state(RecoveryState(stage=RecoveryStages.succeeded))
            except Exception as e:
                set_state(
                    RecoveryState(stage=RecoveryStages.failed, failure_reason=str(e))
                )

        download_and_recover()


@implementer(IStatefulRecoverer)
@define
class StatefulRecoverer:
    """
    An ``IRecoverer`` that exposes changing state as it progresses through the
    recovery process.
    """

    _state: RecoveryState
    _recoverer: IRecoverer

    def recover(self, cap, cursor):
        new_state = self._recoverer.recover(cap, cursor)
        if new_state is not None:
            self._state = new_state
        return None

    def state(self):
        return self._state


@implementer(ILocalRecoverer)
@define
class NullRecoverer:
    """
    An ``IRecoverer`` that does nothing.
    """

    def recover(self, cursor):
        return None


def canned_recoverer(state):
    """
    An ``IStatefulRecoverer`` that always immediately claims whatever you tell
    it to (without actually doing anything).
    """
    return StatefulRecoverer(
        state,
        NullRecoverer(),
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


@implementer(ILocalRecoverer)
@define
class MemorySnapshotRecoverer:
    """
    An ``IRecoverer`` that synchronously loads a snapshot from a list of
    Python strings into the database.
    """

    _statements: List[str]

    def recover(self, cursor):
        """
        Synchronously execute our statement list against the given cursor.
        """
        for sql in self._statements:
            cursor.execute(sql)
        return RecoveryState(stage=RecoveryStages.succeeded)


@implementer(ILocalRecoverer)
@define
class LocalSnapshotRecoverer:
    """
    An ``IRecoverer`` that synchronously loads a snapshot from the local
    filesystem into the database.
    """

    _snapshot: FilePath

    def recover(self, cursor):
        """
        Synchronously execute statements read from the snapshot path against the
        given cursor.
        """
