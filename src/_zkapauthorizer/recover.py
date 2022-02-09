__all__ = [
    "RecoveryState",
    "IRecoverer",
    "SuccessRecoverer",
    "CannedRecoverer",
]

from enum import Enum, auto
from typing import Optional

from attrs import define
from twisted.python.filepath import FilePath
from zope.interface import Interface


class RecoveryStages(Enum):
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

    def marshal(self) -> dict[str, str]:
        return {"stage": self.stage.name, "failure-reason": self.failure_reason}


class IRecoverer(Interface):
    """
    An object which can recover ZKAPAuthorizer state from a replica.
    """

    def recover() -> None:
        """
        Begin the recovery process.

        :raise ValueError: If recovery has already been attempted
            (successfully or otherwise).
        """

    def state() -> RecoveryState:
        """
        Get the current state of the recovery attempt.
        """


@define
class SuccessRecoverer:
    """
    An ``IRecoverer`` that always immediately claims to have succeeded after
    recovery is attempted (without actually doing anything).
    """

    _state: RecoveryState = RecoveryState()

    def recover(self):
        self._state = RecoveryState(stage=RecoveryStages.succeeded)

    def state(self):
        return self._state


@define
class CannedRecoverer:
    """
    An ``IRecoverer`` that always claims whatever you tell it to (without
    doing anything).
    """

    _state: RecoveryState

    def recover(self):
        pass

    def state(self):
        return self._state
