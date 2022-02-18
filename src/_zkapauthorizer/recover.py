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
from io import BytesIO
from sqlite3 import Cursor
from typing import BinaryIO, Callable, Dict, Iterator, Optional

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
            downloaded_data = await download(self._set_state)
        except Exception as e:
            self._set_state(
                RecoveryState(
                    stage=RecoveryStages.download_failed, failure_reason=str(e)
                )
            )
            return

        try:
            recover(statements_from_download(downloaded_data), cursor)
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

    async def fail_downloader(set_state: SetState) -> Awaitable:
        raise reason

    return fail_downloader


def make_canned_downloader(data: bytes) -> Downloader:
    """
    Make a downloader that always immediately succeeds with the given value.
    """
    assert isinstance(data, bytes)

    async def canned_downloader(set_state: SetState) -> Awaitable:
        return BytesIO(data)

    return canned_downloader


# A downloader that does nothing and then succeeds with an empty string.
noop_downloader = make_canned_downloader(b"")


def statements_from_download(data: BinaryIO) -> Iterator[str]:
    """
    Read the SQL statements which constitute the replica from a byte string.
    """
    return data.read().decode("ascii").splitlines()


def recover(statements: Iterator[str], cursor) -> None:
    """
    Synchronously execute our statement list against the given cursor.
    """
    for sql in statements:
        cursor.execute(sql)
