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
A Tahoe-LAFS ``IStorageServer`` implementation which presents passes
per-call to prove authorization for writes and lease updates.

This is the client part of a storage access protocol.  The server part is
implemented in ``_storage_server.py``.
"""

import attr

from zope.interface import (
    implementer,
)
from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
)
from allmydata.interfaces import (
    IStorageServer,
)

from .storage_common import (
    BYTES_PER_PASS,
    required_passes,
    allocate_buckets_message,
    add_lease_message,
    renew_lease_message,
    slot_testv_and_readv_and_writev_message,
    has_writes,
    get_implied_data_length,
)

@implementer(IStorageServer)
@attr.s
class ZKAPAuthorizerStorageClient(object):
    """
    An implementation of the client portion of an access-pass-based
    authorization scheme on top of the basic Tahoe-LAFS storage protocol.

    This ``IStorageServer`` implementation aims to offer the same storage
    functionality as Tahoe-LAFS' built-in storage server but with an added
    layer of pass-based authorization for some operations.  The Python
    interface exposed to application code is the same but the network protocol
    is augmented with passes which are automatically inserted by this class.
    The passes are interpreted by the corresponding server-side implementation
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
        :param unicode message: The message to which to bind the passes.

        :return: A list of passes from ``_get_passes`` encoded into their
            ``bytes`` representation.
        """
        assert isinstance(message, unicode)
        return list(
            t.text.encode("ascii")
            for t
            in self._get_passes(message.encode("utf-8"), count)
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
            self._get_encoded_passes(
                allocate_buckets_message(storage_index),
                required_passes(BYTES_PER_PASS, sharenums, allocated_size),
            ),
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
            self._get_encoded_passes(add_lease_message(storage_index), 1),
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
            self._get_encoded_passes(renew_lease_message(storage_index), 1),
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

    @inlineCallbacks
    def slot_testv_and_readv_and_writev(
            self,
            storage_index,
            secrets,
            tw_vectors,
            r_vector,
    ):
        if has_writes(tw_vectors):
            # When performing writes, if we're increasing the storage
            # requirement, we need to spend more passes.  Unfortunately we
            # don't know what the current storage requirements are at this
            # layer of the system.  It's *likely* that a higher layer does but
            # that doesn't help us, even if it were guaranteed.  So, instead,
            # ask the server.  Invoke a ZKAPAuthorizer-supplied remote method
            # on the storage server that will give us a really good estimate
            # of the current size of all of the specified shares (keys of
            # tw_vectors).
            current_size = yield self._rref.callRemote(
                "slot_share_sizes",
                storage_index,
                set(tw_vectors),
            )
            if current_size is None:
                # The server says it doesn't even know about these shares for
                # this storage index.  Thus, we have not yet paid anything for
                # it and we're about to create it.
                current_pass_count = 0
            else:
                # Compute how much has already been paid for the storage
                # that's already allocated.  We're not required to pay this
                # again.
                current_pass_count = required_passes(BYTES_PER_PASS, {0}, current_size)

            # Determine what the share size which will result from the write
            # we're about to perform.
            implied_sizes = (
                get_implied_data_length(data_vector, length)
                for (_, data_vector, length)
                in tw_vectors.values()
            )
            # Total that across all of the shares and figure how many passes
            # it it would cost if we had to pay for all of it.
            new_size = sum(implied_sizes, 0)
            new_pass_count = required_passes(BYTES_PER_PASS, {0}, new_size)
            # Now compute how much hasn't yet been paid.
            pass_count_increase = new_pass_count - current_pass_count
            # And prepare to pay it.
            passes = self._get_encoded_passes(
                slot_testv_and_readv_and_writev_message(storage_index),
                pass_count_increase,
            )
        else:
            # Non-write operations on slots are free.
            passes = []

        # Perform the operation with the passes we determined are required.
        returnValue((
            yield self._rref.callRemote(
                "slot_testv_and_readv_and_writev",
                passes,
                storage_index,
                secrets,
                tw_vectors,
                r_vector,
            )
        ))

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
