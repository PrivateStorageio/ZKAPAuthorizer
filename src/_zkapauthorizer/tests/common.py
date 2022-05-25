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

from functools import partial
from inspect import iscoroutinefunction
from typing import Awaitable, Callable, TypeVar, Union

from attrs import Factory, define, field
from eliot import log_call
from twisted.internet.defer import Deferred
from twisted.python.reflect import fullyQualifiedName
from zope.interface import classImplements
from zope.interface.interface import InterfaceClass


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
    from twisted.trial.runner import _logObserver

    return _logObserver.flushErrors(exc_type)


_A = TypeVar("_A")


def delayedProxy(iface, obj: _A) -> tuple[_DelayedController, _A]:
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
    controller = _DelayedController()
    originalAttribute = "_original"
    proxyType = proxyForInterface(
        iface,
        partial(controller._descriptorFactory, obj),
        originalAttribute,
    )
    return (controller, proxyType(obj))


@define
class _DelayedController:
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
        self, obj: object, iface: InterfaceClass, name: str, originalName: str
    ) -> Union[Callable, _DelayedMethodDescriptor]:
        """
        Create a delayed method descriptor for a method of the given name.
        """
        function = getattr(type(obj), name)
        if iscoroutinefunction(function):
            return _DelayedMethodDescriptor(function, originalName, self)
        return partial(function, obj)

    def _delayedMethod(self, oself, original) -> _DelayedMethod:
        """
        Create a delayed method wrapper around the given method.
        """
        return _DelayedMethod(self._timeToRun, oself, original)


@define
class _DelayedMethodDescriptor:
    """
    A method descriptor which put a delaying wrapper around the original
    method.
    """

    original_method: Callable
    original_attribute: str
    controller: _DelayedController

    def __get__(self, oself, type=None):
        """
        Retrieve the attribute named ``self.attributeName`` from ``oself``,
        wrapped in a delay method wrapper.
        """
        assert oself is not None
        original = getattr(oself, self.original_attribute)
        return self.controller._delayedMethod(original, self.original_method)


@define
class _DelayedMethod:
    """
    A method wrapper which inserts a delay before calling the original method.
    """

    _timeToRun: Callable[[], Awaitable[None]]
    _original_self: object
    _original_method: Callable

    async def __call__(self, *args, **kwargs):
        """
        Delay and then call the wrapped method.
        """
        await self._timeToRun()
        return await self._original_method(self._original_self, *args, **kwargs)


def proxyForInterface(
    iface: InterfaceClass,
    descriptorFactory: Callable[[InterfaceClass, str, str], object],
    originalAttribute: str = "original",
):
    """
    Create a proxy to an object which exposes descriptors built by the given
    factory for the given interface's methods.

    :param iface: The interface the methods of which will be exposed.

    :param descriptorFactory: A callable for creating the descriptors.

    :param originalAttribute: The name of the attribute where the original
        object will be referenced on the proxy object.
    """

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
    classImplements(proxy, iface)  # type: ignore[misc]
    return proxy


def from_awaitable(a: Awaitable[_A]) -> Deferred[_A]:
    """
    Get a ``Deferred`` that fires with the result of an ``Awaitable``.
    """

    async def adapt() -> _A:
        return await a

    return Deferred.fromCoroutine(adapt())
