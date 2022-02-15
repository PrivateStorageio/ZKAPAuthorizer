"""
A system for recovering local ZKAPAuthorizer state from a remote replica.
"""

__all__ = [
    "AlreadyRecovering",
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
from sqlite3 import Cursor
from typing import Callable, Dict, Optional

from attrs import define


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

    def marshal(self) -> Dict[str, Optional[str]]:
        return {"stage": self.stage.name, "failure-reason": self.failure_reason}


# A function for reporting a change in the state of a recovery attempt.
SetState = Callable[[RecoveryState], None]

# An object which can retrieve remote ZKAPAuthorizer state.
Downloader = Callable[[SetState], Awaitable]


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
    ) -> Awaitable:
        """
        Begin the recovery process.

        :param downloader: A callable which can be used to retrieve a replica.

        :param cursor: A database cursor which can be used to populate the
            database with recovered state.

        :raise AlreadyRecovering: If recovery has already been attempted
            (successfully or otherwise).
        """
        if self._state.stage != RecoveryStages.inactive:
            raise AlreadyRecovering()

        self._set_state(RecoveryState(stage=RecoveryStages.started))
        try:
            await download(self._set_state)
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


def make_fail_downloader(reason: Exception) -> Downloader:
    """
    Make a downloader that always fails with the given exception.
    """

    async def fail_downloader(set_state: SetState) -> Awaitable:
        raise reason

    return fail_downloader


async def noop_downloader(set_state: SetState) -> Awaitable:
    """
    A downloader that does nothing and then succeeds.
    """
