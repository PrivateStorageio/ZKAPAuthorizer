__all__ = [
    "RecoveryState",
    "IRecoverer",
    "canned_recoverer",
    "success_recoverer",
]

from enum import Enum, auto
from sqlite3 import Cursor
from typing import List, Optional

from attrs import define
from twisted.python.filepath import FilePath
from zope.interface import Interface, implementer


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


class IRecoverer(Interface):
    """
    An object which can recover ZKAPAuthorizer state from a replica.
    """

    def recover(cursor: Cursor) -> None:
        """
        Begin the recovery process into the given store.

        :raise ValueError: If recovery has already been attempted
            (successfully or otherwise).
        """


class IStatefulRecoverer(IRecoverer):
    def state() -> RecoveryState:
        """
        Get the current state of the recovery attempt.
        """


@implementer(IStatefulRecoverer)
@define
class StatefulRecoverer:
    """
    An ``IRecoverer`` that exposes changing state as it progresses through the
    recovery process.
    """

    _state: RecoveryState
    _recoverer: IRecoverer

    def recover(self, cursor):
        new_state = self._recoverer.recover(cursor)
        if new_state is not None:
            self._state = new_state
        return None

    def state(self):
        return self._state


@implementer(IRecoverer)
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


def success_recoverer():
    """
    An ``IRecoverer`` that always immediately claims to have succeeded after
    recovery is attempted (without actually doing anything).
    """
    return canned_recoverer(
        RecoveryState(stage=RecoveryStages.succeeded),
    )


@implementer(IRecoverer)
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


@implementer(IRecoverer)
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
