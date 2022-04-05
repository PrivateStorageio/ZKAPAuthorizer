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

from functools import partial, wraps
from typing import Any, Generator, Optional

import attr
from allmydata.interfaces import IStorageServer
from allmydata.util.eliotutil import log_call_deferred
from attr.validators import provides
from eliot.twisted import inline_callbacks
from twisted.internet.defer import Deferred, returnValue
from twisted.internet.interfaces import IReactorTime
from twisted.python.reflect import namedAny
from zope.interface import implementer

from .eliot import CALL_WITH_PASSES, SIGNATURE_CHECK_FAILED
from .storage_common import (
    MorePassesRequired,
    add_lease_message,
    allocate_buckets_message,
    get_required_new_passes_for_mutable_write,
    get_write_sharenums,
    pass_value_attribute,
    required_passes,
    slot_testv_and_readv_and_writev_message,
)

Secrets = tuple[bytes, bytes, bytes]
TestWriteVectors = dict[
    int,
    tuple[
        list[
            tuple[int, int, bytes],
        ],
        list[
            tuple[int, bytes],
        ],
        Optional[int],
    ],
]
ReadVector = list[tuple[int, int]]


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


def invalidate_rejected_passes(passes, more_passes_required):
    """
    Return a new ``IPassGroup`` with all rejected passes removed from it.

    :param IPassGroup passes: A group of passes, some of which may have been
        rejected.

    :param MorePassesRequired more_passes_required: An exception possibly
        detailing the rejection of some passes from the group.

    :return: ``None`` if no passes in the group were rejected and so there is
        nothing to replace.  Otherwise, a new ``IPassGroup`` created from
        ``passes`` but with rejected passes replaced with new ones.
    """
    num_failed = len(more_passes_required.signature_check_failed)
    if num_failed == 0:
        # If no signature checks failed then the call just didn't supply
        # enough passes.  The exception tells us how many passes we should
        # spend so we could try again with that number of passes but for
        # now we'll just let the exception propagate.  The client should
        # always figure out the number of passes right on the first try so
        # this case is somewhat suspicious.  Err on the side of lack of
        # service instead of burning extra passes.
        #
        # We *could* just `raise` here and only be called from an `except`
        # suite... but let's not be so vulgar.
        return None
    SIGNATURE_CHECK_FAILED.log(count=num_failed)
    rejected_passes, okay_passes = passes.split(
        more_passes_required.signature_check_failed
    )
    rejected_passes.mark_invalid("signature check failed")

    # It would be great to just expand okay_passes right here.  However, if
    # that fails (eg because we don't have enough tokens remaining) then the
    # caller will have a hard time figuring out which okay passes remain that
    # it needs to reset. :/ So, instead, pass back the complete okay set.  The
    # caller can figure out by how much to expand it by considering its size
    # and the original number of passes it requested.
    return okay_passes


@inline_callbacks
def call_with_passes_with_manual_spend(method, num_passes, get_passes, on_success):
    """
    Call a method, passing the requested number of passes as the first
    argument, and try again if the call fails with an error related to some of
    the passes being rejected.

    :param (IPassGroup -> Deferred) method: An operation to call with some passes.
        If the returned ``Deferred`` fires with ``MorePassesRequired`` then
        the invalid passes will be discarded and replacement passes will be
        requested for a new call of ``method``.  This will repeat until no
        passes remain, the method succeeds, or the methods fails in a
        different way.

    :param int num_passes: The number of passes to pass to the call.

    :param (int -> IPassGroup) get_passes: A function for getting
        passes.

    :param (object -> IPassGroup -> None) on_success: A function to call when
        ``method`` succeeds.  The first argument is the result of ``method``.
        The second argument is the ``IPassGroup`` used with the successful
        call.  The intended purpose of this hook is to mark as spent passes in
        the group which the method has spent.  This is useful if the result of
        ``method`` can be used to determine the operation had a lower cost
        than the worst-case expected from its inputs.

        Spent passes should be marked as spent.  All others should be reset.

    :return: A ``Deferred`` that fires with whatever the ``Deferred`` returned
        by ``method`` fires with (apart from ``MorePassesRequired`` failures
        that trigger a retry).
    """
    with CALL_WITH_PASSES(count=num_passes):
        pass_group = get_passes(num_passes)
        try:
            # Try and repeat as necessary.
            while True:
                try:
                    result = yield method(pass_group)
                except MorePassesRequired as e:
                    okay_pass_group = invalidate_rejected_passes(
                        pass_group,
                        e,
                    )
                    if okay_pass_group is None:
                        raise
                    else:
                        # Update the local in case we end up going to the
                        # except suite below.
                        pass_group = okay_pass_group
                        # Add the necessary number of new passes.  This might
                        # fail if we don't have enough tokens.
                        pass_group = pass_group.expand(
                            num_passes - len(pass_group.passes)
                        )
                else:
                    on_success(result, pass_group)
                    break
        except:
            # Something went wrong that we can't address with a retry.
            pass_group.reset()
            raise

    # Give the operation's result to the caller.
    returnValue(result)


def call_with_passes(method, num_passes, get_passes):
    """
    Similar to ``call_with_passes_with_manual_spend`` but automatically spend
    all passes associated with a successful call of ``method``.

    For parameter documentation, see ``call_with_passes_with_manual_spend``.
    """
    return call_with_passes_with_manual_spend(
        method,
        num_passes,
        get_passes,
        # Commit the spend of the passes when the operation finally succeeds.
        lambda result, pass_group: pass_group.mark_spent(),
    )


def with_rref(f):
    """
    Decorate a function so that it automatically receives a
    ``RemoteReference`` as its first argument when called.

    The ``RemoteReference`` is retrieved by calling ``_rref`` on the first
    argument passed to the function (expected to be ``self``).
    """

    @wraps(f)
    def g(self, *args, **kwargs):
        return f(self, self._rref(), *args, **kwargs)

    return g


def _encode_passes(group):
    """
    :param IPassGroup group: A group of passes to encode.

    :return list[bytes]: The encoded form of the passes in the given group.
    """
    return list(t.pass_bytes for t in group.passes)


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

    :ivar (bytes -> int -> IPassGroup) _get_passes: A callable to use to
        retrieve passes which can be used to authorize an operation.  The
        first argument is utf-8 encoded message binding the passes to the
        request for which they will be used.  The second gives the number of
        passes to request.
    """

    _expected_remote_interface_name = (
        "RIPrivacyPassAuthorizedStorageServer.tahoe.privatestorage.io"
    )
    _pass_value = pass_value_attribute()
    _get_rref = attr.ib()
    _get_passes = attr.ib()
    _clock = attr.ib(
        validator=provides(IReactorTime),
        default=attr.Factory(partial(namedAny, "twisted.internet.reactor")),
    )

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

    @with_rref
    def get_version(self, rref):
        return rref.callRemote(
            "get_version",
        )

    def _spend_for_allocate_buckets(
        self,
        allocated_size,
        result,
        pass_group,
    ):
        """
        Spend some subset of a pass group based on the results of an
        *allocate_buckets* call.

        :param int allocate_buckets: The size of the shares that may have been
            allocated.

        :param ({int}, {int: IBucketWriter}) result: The result of the remote
            *allocate_buckets* call.

        :param IPassGroup pass_group: The passes which were used with the
            remote call.  A prefix of the passes in this group will be spent
            based on the buckets which ``result`` indicates were actually
            allocated.
        """
        alreadygot, bucketwriters = result
        # Passes only need to be spent for buckets that are being
        # allocated.  Someone already paid for any shares the server
        # already has.
        actual_passes = required_passes(
            self._pass_value,
            [allocated_size] * len(bucketwriters),
        )
        to_spend, to_reset = pass_group.split(range(actual_passes))
        to_spend.mark_spent()
        to_reset.reset()

    @with_rref
    def allocate_buckets(
        self,
        rref,
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        allocated_size,
        canary,
    ):
        num_passes = required_passes(
            self._pass_value, [allocated_size] * len(sharenums)
        )
        return call_with_passes_with_manual_spend(
            lambda passes: rref.callRemote(
                "allocate_buckets",
                _encode_passes(passes),
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                allocated_size,
                canary,
            ),
            num_passes,
            partial(
                self._get_passes,
                allocate_buckets_message(storage_index),
            ),
            partial(self._spend_for_allocate_buckets, allocated_size),
        )

    @with_rref
    def get_buckets(
        self,
        rref,
        storage_index,
    ):
        return rref.callRemote(
            "get_buckets",
            storage_index,
        )

    @inline_callbacks
    @with_rref
    def add_lease(
        self,
        rref,
        storage_index,
        renew_secret,
        cancel_secret,
    ):
        share_sizes = (
            yield rref.callRemote(
                "share_sizes",
                storage_index,
                None,
            )
        ).values()
        num_passes = required_passes(self._pass_value, share_sizes)

        result = yield call_with_passes(
            lambda passes: rref.callRemote(
                "add_lease",
                _encode_passes(passes),
                storage_index,
                renew_secret,
                cancel_secret,
            ),
            num_passes,
            partial(self._get_passes, add_lease_message(storage_index)),
        )
        returnValue(result)

    @with_rref
    def stat_shares(self, rref, storage_indexes):
        return rref.callRemote(
            "stat_shares",
            storage_indexes,
        )

    @with_rref
    def advise_corrupt_share(
        self,
        rref,
        share_type,
        storage_index,
        shnum,
        reason,
    ):
        return rref.callRemote(
            "advise_corrupt_share",
            share_type,
            storage_index,
            shnum,
            reason,
        )

    @log_call_deferred("zkapauthorizer:storage-client:slot_testv_and_readv_and_writev")
    @inline_callbacks
    @with_rref
    def slot_testv_and_readv_and_writev(
        self,
        rref: Any,
        storage_index: bytes,
        secrets: Secrets,
        tw_vectors: TestWriteVectors,
        r_vector: ReadVector,
    ) -> Generator[Deferred[Any], Any, None]:
        # Read operations are free.
        num_passes = 0

        # Convert tw_vectors from the new internal format to the wire format.
        # See https://github.com/tahoe-lafs/tahoe-lafs/pull/1127/files#r716939082
        old_tw_vectors = {
            sharenum: (
                [
                    (offset, length, b"eq", specimen)
                    for (offset, length, specimen) in test_vector
                ],
                data_vectors,
                new_length,
            )
            for (
                sharenum,
                (test_vector, data_vectors, new_length),
            ) in tw_vectors.items()
        }

        write_sharenums = get_write_sharenums(old_tw_vectors)
        if len(write_sharenums) > 0:
            # When performing writes, if we're increasing the storage
            # requirement, we need to spend more passes.  Unfortunately we
            # don't know what the current storage requirements are at this
            # layer of the system.  It's *likely* that a higher layer does but
            # that doesn't help us, even if it were guaranteed.  So, instead,
            # ask the server.  Invoke a ZKAPAuthorizer-supplied remote method
            # on the storage server that will give us a really good estimate
            # of the current size of all of the specified shares (keys of
            # tw_vectors).
            [stats] = yield rref.callRemote(
                "stat_shares",
                [storage_index],
            )
            # Filter down to only the shares that have an active lease.  If
            # we're going to write to any other shares we will have to pay to
            # renew their leases.
            now = self._clock.seconds()
            current_sizes = {
                sharenum: stat.size
                for (sharenum, stat) in stats.items()
                if stat.lease_expiration > now
                # Also, the size of any share we're not writing to doesn't
                # matter.
                and sharenum in write_sharenums
            }
            # Determine the cost of the new storage for the operation.
            num_passes = get_required_new_passes_for_mutable_write(
                self._pass_value,
                current_sizes,
                old_tw_vectors,
            )

        result = yield call_with_passes(
            lambda passes: rref.callRemote(
                "slot_testv_and_readv_and_writev",
                _encode_passes(passes),
                storage_index,
                secrets,
                old_tw_vectors,
                r_vector,
            ),
            num_passes,
            partial(
                self._get_passes,
                slot_testv_and_readv_and_writev_message(storage_index),
            ),
        )
        returnValue(result)

    @with_rref
    def slot_readv(
        self,
        rref,
        storage_index,
        shares,
        r_vector,
    ):
        return rref.callRemote(
            "slot_readv",
            storage_index,
            shares,
            r_vector,
        )
