__all__ = [
    "RecoveryState",
    "IRecoverer",
    "SuccessRecoverer",
    "FailureRecoverer",
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
    state: RecoveryStates = RecoveryStates.inactive
    reason: Optional[str] = None


class IRecoverer(Interface):
    def recover() -> None:
        pass

    def state() -> RecoveryState:
        pass


@define
class SuccessRecoverer:
    _state: RecoveryState = RecoveryState()

    def recover(self):
        self._state = RecoveryState(state=RecoveryStates.succeeded)

    def state(self):
        return self._state


@define
class FailureRecoverer:
    reason: str
    _state: RecoveryState = RecoveryState()

    def recover(self):
        self._state = RecoveryState(state=RecoveryStates.failed, reason=self.reason)

    def state(self):
        return self._state
