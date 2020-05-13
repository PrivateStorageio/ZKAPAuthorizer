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

from functools import (
    partial,
)

import attr

from zope.interface import (
    implementer,
)
from twisted.internet.defer import (
    inlineCallbacks,
    returnValue,
    maybeDeferred,
)
from allmydata.interfaces import (
    IStorageServer,
)

from .storage_common import (
    MorePassesRequired,
    pass_value_attribute,
    required_passes,
    allocate_buckets_message,
    add_lease_message,
    renew_lease_message,
    slot_testv_and_readv_and_writev_message,
    has_writes,
    get_required_new_passes_for_mutable_write,
)


class IncorrectStorageServerReference(Exception):
    """
    A Foolscap remote object which should reference a ZKAPAuthorizer storage
    server instead references some other kind of object.  This makes the
    connection, and thus the configured storage server, unusable.
    """
    def __init__(self, furl, actual_name, expected_name):
        self.furl = furl
        self.actual_name = actual_name
        self.expected_name = expected_name

    def __str__(self):
        return "RemoteReference via {} provides {} instead of {}".format(
            self.furl,
            self.actual_name,
            self.expected_name,
        )


def call_with_passes(method, num_passes, get_passes):
    """
    Call a method, passing the requested number of passes as the first
    argument, and try again if the call fails with an error related to some of
    the passes being rejected.

    :param method: A callable which accepts a list of encoded passes as its
        only argument and returns a ``Deferred``.  If the ``Deferred`` fires
        with ``MorePassesRequired`` then the invalid passes will be discarded
        and replacement passes will be requested for a new call of ``method``.
        This will repeat until no passes remain, the method succeeds, or the
        methods fails in a different way.

    :param int num_passes: The number of passes to pass to the call.

    :param (unicode -> int -> [bytes]) get_passes: A function for getting
        passes.

    :return: Whatever ``method`` returns.
    """
    def get_more_passes(reason):
        reason.trap(MorePassesRequired)
        new_passes = get_passes(len(reason.value.signature_check_failed))
        for idx, new_pass in zip(reason.value.signature_check_failed, new_passes):
            passes[idx] = new_pass
        return go(passes)

    def go(passes):
        d = maybeDeferred(method, passes)
        d.addErrback(get_more_passes)
        return d

    passes = get_passes(num_passes)
    return go(passes)


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
    _expected_remote_interface_name = (
        "RIPrivacyPassAuthorizedStorageServer.tahoe.privatestorage.io"
    )
    _pass_value = pass_value_attribute()
    _get_rref = attr.ib()
    _get_passes = attr.ib()

    @property
    def _rref(self):
        rref = self._get_rref()
        # rref provides foolscap.ipb.IRemoteReference but in practice it is a
        # foolscap.referenceable.RemoteReference instance.  The interface
        # doesn't give us enough functionality to verify that the reference is
        # to the right sort of thing but the concrete type does.
        #
        # Foolscap development isn't exactly racing along and if we're lucky
        # we'll switch to HTTP before too long anyway.
        actual_name = rref.tracker.interfaceName
        expected_name = self._expected_remote_interface_name
        if actual_name != expected_name:
            raise IncorrectStorageServerReference(
                rref.tracker.getURL(),
                actual_name,
                expected_name,
            )
        return rref

    def _get_encoded_passes(self, message, count):
        """
        :param unicode message: The message to which to bind the passes.

        :return: A list of passes from ``_get_passes`` encoded into their
            ``bytes`` representation.
        """
        assert isinstance(message, unicode)
        return list(
            t.pass_text.encode("ascii")
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
        # XXX _rref is a property and reading it does some stuff that needs to
        # happen before we get passes.  Read it eagerly here.  Blech.
        rref = self._rref
        message = allocate_buckets_message(storage_index)
        num_passes = required_passes(self._pass_value, [allocated_size] * len(sharenums))
        return call_with_passes(
            lambda passes: rref.callRemote(
                "allocate_buckets",
                passes,
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                allocated_size,
                canary,
            ),
            num_passes,
            partial(self._get_encoded_passes, message),
        )

    def get_buckets(
            self,
            storage_index,
    ):
        return self._rref.callRemote(
            "get_buckets",
            storage_index,
        )

    @inlineCallbacks
    def add_lease(
            self,
            storage_index,
            renew_secret,
            cancel_secret,
    ):
        share_sizes = (yield self._rref.callRemote(
            "share_sizes",
            storage_index,
            None,
        )).values()
        num_passes = required_passes(self._pass_value, share_sizes)
        # print("Adding lease to {!r} with sizes {} with {} passes".format(
        #     storage_index,
        #     share_sizes,
        #     num_passes,
        # ))
        returnValue((
            yield self._rref.callRemote(
                "add_lease",
                self._get_encoded_passes(add_lease_message(storage_index), num_passes),
                storage_index,
                renew_secret,
                cancel_secret,
            )
        ))

    @inlineCallbacks
    def renew_lease(
            self,
            storage_index,
            renew_secret,
    ):
        share_sizes = (yield self._rref.callRemote(
            "share_sizes",
            storage_index,
            None,
        )).values()
        num_passes = required_passes(self._pass_value, share_sizes)
        returnValue((
            yield self._rref.callRemote(
                "renew_lease",
                self._get_encoded_passes(renew_lease_message(storage_index), num_passes),
                storage_index,
                renew_secret,
            )
        ))

    def stat_shares(self, storage_indexes):
        return self._rref.callRemote(
            "stat_shares",
            storage_indexes,
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
        # Non-write operations on slots are free.
        passes = []

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
            current_sizes = yield self._rref.callRemote(
                "share_sizes",
                storage_index,
                set(tw_vectors),
            )
            # Determine the cost of the new storage for the operation.
            required_new_passes = get_required_new_passes_for_mutable_write(
                self._pass_value,
                current_sizes,
                tw_vectors,
            )
            # Prepare to pay it.
            if required_new_passes:
                passes = self._get_encoded_passes(
                    slot_testv_and_readv_and_writev_message(storage_index),
                    required_new_passes,
                )

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
