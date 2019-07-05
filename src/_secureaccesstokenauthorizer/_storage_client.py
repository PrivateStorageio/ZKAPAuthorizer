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
class SecureAccessTokenAuthorizerStorageClient(object):
    """
    XXX
    """
    _get_rref = attr.ib()
    _get_tokens = attr.ib()

    @property
    def _rref(self):
        return self._get_rref()

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
            self._get_tokens(),
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
            self._get_tokens(),
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
            self._get_tokens(),
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
