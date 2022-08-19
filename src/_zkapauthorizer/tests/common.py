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
Testing functionality that is specifically related to the test harness
itself.
"""

from __future__ import annotations

from datetime import timedelta
from functools import partial
from inspect import iscoroutinefunction
from typing import Awaitable, Callable, Generic, Optional, TypeAlias, TypeVar, Union

from attrs import Factory, define, field
from twisted.internet.defer import Deferred, succeed
from twisted.internet.task import Clock
from twisted.python.reflect import fullyQualifiedName
from typing_extensions import Concatenate, ParamSpec
from zope.interface import Interface, directlyProvides, providedBy
from zope.interface.interface import InterfaceClass

from ..config import Config
from ..eliot import log_call
from ..foolscap import ShareStat

GetConfig: TypeAlias = Callable[[str, str], Config]


def skipIf(condition, reason):
    """
    Create a decorate a function to be skipped if the given condition is true.

    :param bool condition: The condition under which to skip.
    :param unicode reason: A reason for the skip.

    :return: A function decorator which will skip the test if the given
        condition is true.
    """
    if condition:
        return _skipper(reason)
    return lambda x: x


def _skipper(reason):
    def wrapper(f):
        def skipIt(self, *a, **kw):
            self.skipTest(reason)

        return skipIt

    return wrapper


def flushErrors(exc_type: type) -> list[Exception]:
    """
    Flush logged exceptions of the given type from the Trial log observer.

    :return: A list of the flushed exceptions.
    """
    # There is no public API for flushing logged errors if you're not
    # using one of trial's TestCase classes...
    from twisted.trial.runner import _logObserver  # type: ignore[attr-defined]

    return _logObserver.flushErrors(exc_type)


_A = TypeVar("_A")
_I = TypeVar("_I", bound=Interface)


def delayedProxy(iface: InterfaceClass, obj: _I) -> tuple[_DelayedController[_I], _I]:
    """
    Wrap ``obj`` in a proxy for ``iface`` which inserts an arbitrary delay
    prior to the execution of each method.

    For example::

        foo = make_foo()
        controller, proxy = delayedProxy(IFoo, foo)

        # some_async_method will not actually be called yet
        d = Deferred.fromCoroutine(proxy.some_async_method())

        # Let the call happen
        controller.run()

        # do something with d if you like

    :note: If you do not start the coroutine (eg by using `await` or
        `Deferred.fromCoroutine` on it) then the controller will never see the
        call and `controller.run()` will have no effect.

    :return: A two-tuple of a controller for the proxy and the proxy itself.
    """
    controller: _DelayedController[_I] = _DelayedController()
    originalAttribute = "_original"
    proxyObj = proxyForObject(
        obj,
        partial(controller._descriptorFactory, obj),
        originalAttribute,
    )
    assert iface.providedBy(proxyObj)
    return (controller, proxyObj)


@define
class _DelayedController(Generic[_A]):
    """
    Control when the methods of a delayed proxy are allowed to run.

    :ivar _waiting: Deferreds on which the execution of some delayed method
        call is waiting.
    """

    _waiting: list[Deferred[None]] = field(default=Factory(list))

    @log_call(action_type="zkapauthorizer:tests:delayed-controller:run")
    def run(self) -> None:
        """
        Run all methods which have been called (and delayed) up to this point.

        :raise: ``ValueError`` if there is nothing waiting.
        """
        if len(self._waiting) == 0:
            raise ValueError("Nothing is waiting")
        waiters = self._waiting
        self._waiting = []
        for d in waiters:
            d.callback(None)

    async def _timeToRun(self) -> None:
        """
        A hook for ``_DelayedMethod`` to call each time it is called which returns
        an awaitable which completes when the delayed method should begin
        executing.
        """
        d: Deferred[None] = Deferred()
        self._waiting.append(d)
        await d

    def _descriptorFactory(
        self, obj: _A, iface: InterfaceClass, name: str, originalName: str
    ) -> Union[Callable[_P, _B], _DelayedMethodDescriptor[_A, _B, _P]]:
        """
        Create a delayed method descriptor for a method of the given name.
        """
        function = getattr(type(obj), name)
        if iscoroutinefunction(function):
            return _DelayedMethodDescriptor(function, originalName, self)
        return partial(function, obj)

    def _delayedMethod(
        self, oself: _A, original: Callable[Concatenate[_A, _P], Awaitable[_B]]
    ) -> _DelayedMethod[_A, _B, _P]:
        """
        Create a delayed method wrapper around the given method.
        """
        return _DelayedMethod(self._timeToRun, oself, original)


_P = ParamSpec("_P")
_B = TypeVar("_B")


@define
class _DelayedMethodDescriptor(Generic[_A, _B, _P]):
    """
    A method descriptor which put a delaying wrapper around the original
    method.
    """

    original_method: Callable[Concatenate[_A, _P], Awaitable[_B]]
    original_attribute: str
    controller: _DelayedController[_A]

    def __get__(
        self, oself: _A, type: Optional[type] = None
    ) -> _DelayedMethod[_A, _B, _P]:
        """
        Retrieve the attribute named ``self.attributeName`` from ``oself``,
        wrapped in a delay method wrapper.
        """
        assert oself is not None
        original = getattr(oself, self.original_attribute)
        return self.controller._delayedMethod(original, self.original_method)


@define
class _DelayedMethod(Generic[_A, _B, _P]):
    """
    A method wrapper which inserts a delay before calling the original method.
    """

    _timeToRun: Callable[[], Awaitable[None]]
    _original_self: _A
    _original_method: Callable[Concatenate[_A, _P], Awaitable[_B]]

    async def __call__(self, *args: _P.args, **kwargs: _P.kwargs) -> _B:
        """
        Delay and then call the wrapped method.
        """
        await self._timeToRun()
        return await self._original_method(self._original_self, *args, **kwargs)


def proxyForObject(
    o: _I,
    descriptorFactory: Callable[[InterfaceClass, str, str], object],
    originalAttribute: str = "original",
) -> _I:
    """
    Create an object that proxies access to another object via descriptors
    built by the given factory for the interfaces provided by the original
    value.

    :param o: The original object.

    :param descriptorFactory: A callable which can create the proxy
        descriptors.

    :param originalAttribute: An attribute name on the proxy object at which
        the original object will be accessible.
    """

    ifaces = list(providedBy(o))
    if len(ifaces) != 1:
        raise ValueError(
            f"Cannot determine proxy interface for {o!r} from among {ifaces!r}"
        )

    [iface] = ifaces

    def __init__(self, original):
        setattr(self, originalAttribute, original)

    # It usually doesn't make sense to proxy `__init__` (the wrapped object
    # must already have been initialized by the time we get it) so we don't
    # support it here, but maybe some generalization could change that.
    contents: dict[str, object] = {"__init__": __init__}

    # Use the supplied descriptor factory to create a descriptor for each
    # method/attribute defined by the interface.
    for name in iface.names():
        contents[name] = descriptorFactory(iface, name, originalAttribute)

    # Create a type with all the attributes we just defined.
    proxy = type(f"(Proxy for {fullyQualifiedName(iface)})", (object,), contents)

    # mypy-zope declarations.classImplements only works when passing a
    # concrete class type.  ignore the error produced by trying to use it on
    # our dynamically constructed class.
    # classImplements(proxy, iface)  # type: ignore[misc]

    proxyObj = proxy(o)
    directlyProvides(proxyObj, iface)
    return proxyObj


# def proxyForInterface(
#     iface: InterfaceClass,
#     descriptorFactory: Callable[[InterfaceClass, str, str], object],
#     originalAttribute: str = "original",
# ) -> InterfaceClass:
#     """
#     Create a type that proxies access to an object via descriptors built
#     by the given factory for the given interface's methods.

#     :param iface: The interface the methods of which will be exposed.

#     :param descriptorFactory: A callable for creating the descriptors.

#     :param originalAttribute: The name of the attribute where the original
#         object will be referenced on the proxy object.
#     """

#     def __init__(self, original):
#         setattr(self, originalAttribute, original)

#     # It usually doesn't make sense to proxy `__init__` (the wrapped object
#     # must already have been initialized by the time we get it) so we don't
#     # support it here, but maybe some generalization could change that.
#     contents: dict[str, object] = {"__init__": __init__}

#     # Use the supplied descriptor factory to create a descriptor for each
#     # method/attribute defined by the interface.
#     for name in iface.names():
#         contents[name] = descriptorFactory(iface, name, originalAttribute)

#     # Create a type with all the attributes we just defined.
#     proxy = type(f"(Proxy for {fullyQualifiedName(iface)})", (object,), contents)

#     # mypy-zope declarations.classImplements only works when passing a
#     # concrete class type.  ignore the error produced by trying to use it on
#     # our dynamically constructed class.
#     classImplements(proxy, iface)  # type: ignore[misc]
#     return proxy


def from_awaitable(a: Awaitable[_A]) -> Deferred[_A]:
    """
    Get a ``Deferred`` that fires with the result of an ``Awaitable``.
    """

    async def adapt() -> _A:
        return await a

    return Deferred.fromCoroutine(adapt())


@define
class DummyStorageServer(object):
    """
    A dummy implementation of ``IStorageServer`` from Tahoe-LAFS.

    :ivar buckets: A mapping from storage index to
        metadata about shares at that storage index.
    """

    clock: Clock
    buckets: dict[bytes, dict[int, ShareStat]]
    lease_seed: bytes

    def stat_shares(
        self, storage_indexes: list[bytes]
    ) -> Deferred[list[dict[int, ShareStat]]]:
        return succeed(list(self.buckets.get(idx, {}) for idx in storage_indexes))

    def get_lease_seed(self):
        return self.lease_seed

    def add_lease(self, storage_index, renew_secret, cancel_secret):
        for stat in self.buckets.get(storage_index, {}).values():
            stat.lease_expiration = int(
                self.clock.seconds() + timedelta(days=31).total_seconds()
            )
