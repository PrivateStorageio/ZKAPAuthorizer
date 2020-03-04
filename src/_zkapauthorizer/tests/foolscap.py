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

from __future__ import (
    absolute_import,
)

from zope.interface import (
    implementer,
)

import attr

from twisted.internet.defer import (
    execute,
)

from foolscap.api import (
    RemoteInterface,
)

from allmydata.interfaces import (
    RIStorageServer,
)

class RIStub(RemoteInterface):
    pass

@implementer(RIStorageServer)
class StubStorageServer(object):
    pass


def get_anonymous_storage_server():
    return StubStorageServer()


@attr.s
class DummyReferenceable(object):
    _interface = attr.ib()

    def getInterface(self):
        return self._interface

    def doRemoteCall(self, *a, **kw):
        return None

@attr.s
class LocalTracker(object):
    """
    Pretend to be a tracker for a ``LocalRemote``.
    """
    interface = attr.ib()
    interfaceName = attr.ib(default=None)

    def __attrs_post_init__(self):
        self.interfaceName = self.interface.__remote_name__

    def getURL(self):
        return b"pb://abcd@127.0.0.1:12345/efgh"


@attr.s
class LocalRemote(object):
    """
    Adapt a referenceable to behave as if it were a remote reference instead.

    This is only a partial implementation of ``IRemoteReference`` so it
    doesn't declare the interface.

    ``foolscap.referenceable.LocalReferenceable`` is in many ways a better
    adapter between these interfaces but it also uses ``eventually`` which
    complicates matters immensely for testing.

    :ivar foolscap.ipb.IReferenceable _referenceable: The object to which this
        provides a simulated remote interface.
    """
    _referenceable = attr.ib()
    check_args = attr.ib(default=True)
    tracker = attr.ib(default=None)

    def __attrs_post_init__(self):
        self.tracker = LocalTracker(
            self._referenceable.getInterface(),
        )

    def callRemote(self, methname, *args, **kwargs):
        """
        Call the given method on the wrapped object, passing the given arguments.

        Arguments are checked for conformance to the remote interface but the
        return value is not (because I don't know how -exarkun).

        :return Deferred: The result of the call on the wrapped object.
        """
        schema = self._referenceable.getInterface()[methname]
        if self.check_args:
            schema.checkAllArgs(args, kwargs, inbound=False)
        # TODO: Figure out how to call checkResults on the result.
        return execute(
            self._referenceable.doRemoteCall,
            methname,
            args,
            kwargs,
        )
