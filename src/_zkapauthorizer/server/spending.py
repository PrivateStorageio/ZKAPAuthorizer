from typing import Any

import attr
from challenge_bypass_ristretto import PublicKey
from prometheus_client import CollectorRegistry
from twisted.internet.interfaces import IReactorTime
from zope.interface import Interface, implementer


class ISpender(Interface):
    """
    An ``ISpender`` can records spent ZKAPs and reports double spends.
    """

    def mark_as_spent(public_key: PublicKey, passes: list[bytes]) -> None:
        """
        Record the given ZKAPs (associated to the given public key as having
        been spent.

        This does *not* report errors and should only be used in cases when
        recording spending that has already happened. This can be because
        we could not contact the spending service when they were spent, or
        because we can't yet check before making changes to the node.
        """


@attr.s
class _SpendingData(object):
    spent_tokens = attr.ib(init=False, factory=dict)

    def reset(self):
        self.spent_tokens.clear()


@implementer(ISpender)
@attr.s
class RecordingSpender(object):
    """
    An in-memory :py:`ISpender` implementation that exposes the spent tokens
    for testing purposes.
    """

    _recorder = attr.ib(validator=attr.validators.instance_of(_SpendingData))

    @classmethod
    def make(cls) -> tuple[_SpendingData, ISpender]:
        recorder = _SpendingData()
        return recorder, cls(recorder)

    def mark_as_spent(self, public_key, passes):
        self._recorder.spent_tokens.setdefault(public_key.encode_base64(), []).extend(
            passes
        )


def get_spender(
    config: dict[str, Any], reactor: IReactorTime, registry: CollectorRegistry
) -> ISpender:
    """
    Return an :py:`ISpender` to be used with the given storage server configuration.
    """
    recorder, spender = RecordingSpender.make()
    return spender
