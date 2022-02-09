__all__ = [
    "RecoveryState",
    "IRecoverer",
    "SuccessRecoverer",
    "CannedRecoverer",
]

from enum import Enum, auto
from typing import Optional

from attrs import define
from zope.interface import Interface


class RecoveryStates(Enum):
    inactive = auto
    succeeded = auto


@define(frozen=True)
class RecoveryState:
    """
    Describe the state of an attempt at recovery.

    :ivar state: The recovery process progresses through different stages.
        This indicates the point which that progress has reached.

    :ivar failure_reason: If the recovery failed then a human-meaningful
        (maybe) string giving details about why.
    """

    stage: RecoveryStates = RecoveryStates.inactive
    failure_reason: Optional[str] = None


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
    An ``IRecoverer`` that always immediately claims to have succeeded
    (without doing anything).
    """

    _state: RecoveryState = RecoveryState()

    def recover(self):
        self._state = RecoveryState(stage=RecoveryStates.succeeded)

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
