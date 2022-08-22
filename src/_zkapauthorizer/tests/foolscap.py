# Copyright 2019 PrivateStorage.io, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Testing helpers related to Foolscap.
"""

from typing import Awaitable, Iterable, NoReturn, Type, TypeVar

from attrs import define, field, frozen
from foolscap.api import (  # type: ignore[attr-defined]
    Any,
    Copyable,
    Referenceable,
    RemoteInterface,
)
from foolscap.copyable import CopyableSlicer, ICopyable
from foolscap.referenceable import RemoteReference
from twisted.internet.defer import fail, succeed
from zope.interface import Interface, implementer


class RIStub(RemoteInterface):
    pass


class RIEcho(RemoteInterface):
    def echo(argument=Any()):  # type: ignore[no-untyped-def]
        return Any()


class StubStorageServer(object):
    def register_bucket_writer_close_handler(self, handler: object) -> None:
        pass


def get_anonymous_storage_server() -> StubStorageServer:
    return StubStorageServer()


class BrokenCopyable(Copyable):
    """
    I don't have a ``typeToCopy`` so I can't be serialized.
    """


T = TypeVar("T")


@implementer(
    RIEcho  # type: ignore # zope.interface.implementer accepts interface, not ...
)
class Echoer(Referenceable):
    def remote_echo(self, argument: T) -> T:
        return argument


@frozen
class DummyReferenceable(object):
    _interface: Type[Interface]

    def getInterface(self) -> Type[Interface]:
        return self._interface

    def doRemoteCall(self, *a: object, **kw: object) -> object:
        return None


@define
class LocalTracker(object):
    """
    Pretend to be a tracker for a ``LocalRemote``.
    """

    interface: Type[RemoteInterface]
    interfaceName: str = field(init=False)

    @interfaceName.default
    def _interfaceName_default(self) -> str:
        return self.interface.__remote_name__  # type: ignore[no-any-return]

    def getURL(self) -> str:
        return "pb://abcd@127.0.0.1:12345/efgh"


@define
class LocalRemote(RemoteReference):
    """
    Adapt a referenceable to behave as if it were a remote reference instead.

    ``foolscap.referenceable.LocalReferenceable`` is in many ways a better
    adapter between these interfaces but it also uses ``eventually`` which
    complicates matters immensely for testing.

    :ivar _referenceable: The object to which this provides a simulated remote
        interface.
    """

    _referenceable: Referenceable
    check_args: bool = True
    tracker: LocalTracker = field()

    @tracker.default
    def _tracker_default(self) -> LocalTracker:
        return LocalTracker(
            self._referenceable.getInterface(),
        )

    def notifyOnDisconnect(
        self, callback: object, *args: object, **kwargs: object
    ) -> NoReturn:
        raise NotImplementedError()

    def dontNotifyOnDisconnect(self, cookie: object) -> NoReturn:
        raise NotImplementedError()

    def callRemoteOnly(self, _name: Any, *args: Any, **kwargs: Any) -> NoReturn:
        raise NotImplementedError()

    def callRemote(self, _name: Any, *args: Any, **kwargs: Any) -> Awaitable[object]:
        """
        Call the given method on the wrapped object, passing the given arguments.

        Arguments and return are checked for conformance to the remote
        interface but they are not actually serialized.

        :return Deferred: The result of the call on the wrapped object.
        """
        try:
            schema = self._referenceable.getInterface()[_name]
            if self.check_args:
                schema.checkAllArgs(args, kwargs, inbound=True)
            _check_copyables(list(args) + list(kwargs.values()))
            result = self._referenceable.doRemoteCall(
                _name,
                args,
                kwargs,
            )
            schema.checkResults(result, inbound=False)
            _check_copyables([result])
            return succeed(result)
        except:
            return fail()


def _check_copyables(copyables: Iterable[object]) -> None:
    """
    Check each object to see if it is a copyable and if it is make sure it can
    be sliced.
    """
    for obj in copyables:
        if ICopyable.providedBy(obj):
            list(CopyableSlicer(obj).slice(False, None))
        elif isinstance(obj, dict):
            _check_copyables(obj.values())
        elif isinstance(obj, list):
            _check_copyables(obj)
