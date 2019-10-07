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
A Tahoe-LAFS ``IStorageServer`` implementation which presents tokens
per-call to prove authorization for writes and lease updates.

This is the client part of a storage access protocol.  The server part is
implemented in ``_storage_server.py``.
"""

import attr

from zope.interface import (
    implementer,
)

from allmydata.interfaces import (
    IStorageServer,
)

@implementer(IStorageServer)
@attr.s
class ZKAPAuthorizerStorageClient(object):
    """
    An implementation of the client portion of an access-token-based
    authorization scheme on top of the basic Tahoe-LAFS storage protocol.

    This ``IStorageServer`` implementation aims to offer the same storage
    functionality as Tahoe-LAFS' built-in storage server but with an added
    layer of token-based authorization for some operations.  The Python
    interface exposed to application code is the same but the network protocol
    is augmented with tokens which are automatically inserted by this class.
    The tokens are interpreted by the corresponding server-side implementation
    of this scheme.

    :ivar _get_rref: A no-argument callable which retrieves the most recently
        valid ``RemoteReference`` corresponding to the server-side object for
        this scheme.

    :ivar _get_passes: A two-argument callable which retrieves some passes
        which can be used to authorize an operation.  The first argument is a
        bytes (valid utf-8) message binding the passes to the request for
        which they will be used.  The second is an integer giving the number
        of passes to request.
    """
    _get_rref = attr.ib()
    _get_passes = attr.ib()

    @property
    def _rref(self):
        return self._get_rref()

    def _get_encoded_passes(self, message, count):
        """
        :return: A list of passes from ``_get_passes`` encoded into their
            ``bytes`` representation.
        """
        return list(
            t.text.encode("ascii")
            for t
            in self._get_passes(message.encode("hex"), count)
        )

    def get_version(self):
        return self._rref.callRemote(
            "get_version",
        )

    def allocate_buckets(
            self,
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            allocated_size,
            canary,
    ):
        return self._rref.callRemote(
            "allocate_buckets",
            self._get_encoded_passes(storage_index, 1),
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            allocated_size,
            canary,
        )

    def get_buckets(
            self,
            storage_index,
    ):
        return self._rref.callRemote(
            "get_buckets",
            storage_index,
        )

    def add_lease(
            self,
            storage_index,
            renew_secret,
            cancel_secret,
    ):
        return self._rref.callRemote(
            "add_lease",
            self._get_encoded_passes(storage_index, 1),
            storage_index,
            renew_secret,
            cancel_secret,
        )

    def renew_lease(
            self,
            storage_index,
            renew_secret,
    ):
        return self._rref.callRemote(
            "renew_lease",
            self._get_encoded_passes(storage_index, 1),
            storage_index,
            renew_secret,
        )

    def advise_corrupt_share(
            self,
            share_type,
            storage_index,
            shnum,
            reason,
    ):
        return self._rref.callRemote(
            "advise_corrupt_share",
            share_type,
            storage_index,
            shnum,
            reason,
        )

    def slot_testv_and_readv_and_writev(
            self,
            storage_index,
            secrets,
            tw_vectors,
            r_vector,
    ):
        return self._rref.callRemote(
            "slot_testv_and_readv_and_writev",
            self._get_encoded_passes(storage_index, 1),
            storage_index,
            secrets,
            tw_vectors,
            r_vector,
        )

    def slot_readv(
            self,
            storage_index,
            shares,
            r_vector,
    ):
        return self._rref.callRemote(
            "slot_readv",
            storage_index,
            shares,
            r_vector,
        )
