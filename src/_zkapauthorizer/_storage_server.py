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
A Tahoe-LAFS RIStorageServer-alike which authorizes writes and lease
updates using per-call passes.

This is the server part of a storage access protocol.  The client part is
implemented in ``_storage_client.py``.
"""

from __future__ import (
    absolute_import,
)

from struct import (
    unpack,
    calcsize,
)

from errno import (
    ENOENT,
)

from functools import (
    partial,
)

from os.path import (
    join,
)
from os import (
    listdir,
)
from datetime import (
    timedelta,
)
import attr
from attr.validators import (
    provides,
    instance_of,
)

from zope.interface import (
    implementer_only,
)
from foolscap.api import (
    Referenceable,
)
from foolscap.ipb import (
    IReferenceable,
    IRemotelyCallable,
)
from allmydata.interfaces import (
    RIStorageServer,
)
from allmydata.storage.common import (
    storage_index_to_dir,
)
from challenge_bypass_ristretto import (
    TokenPreimage,
    VerificationSignature,
    SigningKey,
)

from twisted.python.reflect import (
    namedAny,
)
from twisted.internet.interfaces import (
    IReactorTime,
)

from .foolscap import (
    ShareStat,
    RIPrivacyPassAuthorizedStorageServer,
)
from .storage_common import (
    BYTES_PER_PASS,
    required_passes,
    allocate_buckets_message,
    add_lease_message,
    renew_lease_message,
    slot_testv_and_readv_and_writev_message,
    has_writes,
    get_required_new_passes_for_mutable_write,
)

# See allmydata/storage/mutable.py
SLOT_HEADER_SIZE = 468
LEASE_TRAILER_SIZE = 4

class MorePassesRequired(Exception):
    """
    Storage operations fail with ``MorePassesRequired`` when they are not
    accompanied by a sufficient number of valid passes.

    :ivar int valid_count: The number of valid passes presented in the
        operation.

    ivar int required_count: The number of valid passes which must be
        presented for the operation to be authorized.
    """
    def __init__(self, valid_count, required_count):
        self.valid_count = valid_count
        self.required_count = required_count

    def __repr__(self):
        return "MorePassedRequired(valid_count={}, required_count={})".format(
            self.valid_count,
            self.required_count,
        )

    def __str__(self):
        return repr(self)


class LeaseRenewalRequired(Exception):
    """
    Mutable write operations fail with ``LeaseRenewalRequired`` when the slot
    which is the target of the write does not have an active lease and no
    passes are supplied to create one.
    """


@implementer_only(RIPrivacyPassAuthorizedStorageServer, IReferenceable, IRemotelyCallable)
# It would be great to use `frozen=True` (value-based hashing) instead of
# `cmp=False` (identity based hashing) but Referenceable wants to set some
# attributes on self and it's hard to avoid that.
@attr.s(cmp=False)
class ZKAPAuthorizerStorageServer(Referenceable):
    """
    A class which wraps an ``RIStorageServer`` to insert pass validity checks
    before allowing certain functionality.
    """

    # This is the amount of time an added or renewed lease will last.  We
    # duplicate the value used by the underlying anonymous-access storage
    # server which does not expose it via a Python API or allow it to be
    # configured or overridden.  It would be great if the anonymous-access
    # storage server eventually made lease time a parameter so we could just
    # control it ourselves.
    LEASE_PERIOD = timedelta(days=31)

    _original = attr.ib(validator=provides(RIStorageServer))
    _signing_key = attr.ib(validator=instance_of(SigningKey))
    _clock = attr.ib(
        validator=provides(IReactorTime),
        default=attr.Factory(partial(namedAny, "twisted.internet.reactor")),
    )

    def _is_invalid_pass(self, message, pass_):
        """
        Cryptographically check the validity of a single pass.

        :param unicode message: The shared message for pass validation.
        :param bytes pass_: The encoded pass to validate.

        :return bool: ``False`` (invalid) if the pass includes a valid
            signature, ``True`` (valid) otherwise.
        """
        assert isinstance(message, unicode), "message %r not unicode" % (message,)
        assert isinstance(pass_, bytes), "pass %r not bytes" % (pass_,)
        try:
            preimage_base64, signature_base64 = pass_.split(b" ")
            preimage = TokenPreimage.decode_base64(preimage_base64)
            proposed_signature = VerificationSignature.decode_base64(signature_base64)
            unblinded_token = self._signing_key.rederive_unblinded_token(preimage)
            verification_key = unblinded_token.derive_verification_key_sha512()
            invalid_pass = verification_key.invalid_sha512(proposed_signature, message.encode("utf-8"))
            return invalid_pass
        except Exception:
            # It would be pretty nice to log something here, sometimes, I guess?
            return True

    def _validate_passes(self, message, passes):
        """
        Check all of the given passes for validity.

        :param unicode message: The shared message for pass validation.
        :param list[bytes] passes: The encoded passes to validate.

        :return list[bytes]: The passes which are found to be valid.
        """
        result = list(
            pass_
            for pass_
            in passes
            if not self._is_invalid_pass(message, pass_)
        )
        # print("{}: {} passes, {} valid".format(message, len(passes), len(result)))
        return result

    def remote_get_version(self):
        """
        Pass-through without pass check to allow clients to learn about our
        version and configuration in case it helps them decide how to behave.
        """
        return self._original.remote_get_version()

    def remote_allocate_buckets(self, passes, storage_index, renew_secret, cancel_secret, sharenums, allocated_size, canary):
        """
        Pass-through after a pass check to ensure that clients can only allocate
        storage for immutable shares if they present valid passes.
        """
        valid_passes = self._validate_passes(
            allocate_buckets_message(storage_index),
            passes,
        )
        check_pass_quantity_for_write(len(valid_passes), sharenums, allocated_size)

        return self._original.remote_allocate_buckets(
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            allocated_size,
            canary,
        )

    def remote_get_buckets(self, storage_index):
        """
        Pass-through without pass check to let clients read immutable shares as
        long as those shares exist.
        """
        return self._original.remote_get_buckets(storage_index)

    def remote_add_lease(self, passes, storage_index, *a, **kw):
        """
        Pass-through after a pass check to ensure clients can only extend the
        duration of share storage if they present valid passes.
        """
        # print("server add_lease({}, {!r})".format(len(passes), storage_index))
        valid_passes = self._validate_passes(add_lease_message(storage_index), passes)
        check_pass_quantity_for_lease(
            storage_index,
            valid_passes,
            self._original,
        )
        return self._original.remote_add_lease(storage_index, *a, **kw)

    def remote_renew_lease(self, passes, storage_index, *a, **kw):
        """
        Pass-through after a pass check to ensure clients can only extend the
        duration of share storage if they present valid passes.
        """
        valid_passes = self._validate_passes(renew_lease_message(storage_index), passes)
        check_pass_quantity_for_lease(
            storage_index,
            valid_passes,
            self._original,
        )
        return self._original.remote_renew_lease(storage_index, *a, **kw)

    def remote_advise_corrupt_share(self, *a, **kw):
        """
        Pass-through without a pass check to let clients inform us of possible
        issues with the system without incurring any cost to themselves.
        """
        return self._original.remote_advise_corrupt_share(*a, **kw)

    def remote_share_sizes(self, storage_index_or_slot, sharenums):
        return dict(
            get_share_sizes(self._original, storage_index_or_slot, sharenums)
        )

    def remote_stat_shares(self, storage_indexes_or_slots):
        return list(
            dict(stat_share(self._original, storage_index_or_slot))
            for storage_index_or_slot
            in storage_indexes_or_slots
        )

    def remote_slot_testv_and_readv_and_writev(
            self,
            passes,
            storage_index,
            secrets,
            tw_vectors,
            r_vector,
    ):
        """
        Pass-through after a pass check to ensure clients can only allocate
        storage for mutable shares if they present valid passes.

        :note: This method can be used both to allocate storage and to rewrite
            data in already-allocated storage.  These cases may not be the
            same from the perspective of pass validation.
        """
        # Only writes to shares without an active lease will result in a lease
        # renewal.
        renew_leases = False

        if has_writes(tw_vectors):
            # Passes may be supplied with the write to create the
            # necessary lease as part of the same operation.  This must be
            # supported because there is no separate protocol action to
            # *create* a slot.  Clients just begin writing to it.
            valid_passes = self._validate_passes(
                slot_testv_and_readv_and_writev_message(storage_index),
                passes,
            )
            if has_active_lease(self._original, storage_index, self._clock.seconds()):
                # Some of the storage is paid for already.
                current_sizes = dict(get_share_sizes(
                    self._original,
                    storage_index,
                    tw_vectors.keys(),
                ))
                # print("has writes, has active lease, current sizes: {}".format(current_sizes))
            else:
                # None of it is.
                current_sizes = {}
                renew_leases = True

            required_new_passes = get_required_new_passes_for_mutable_write(
                current_sizes,
                tw_vectors,
            )
            if required_new_passes > len(valid_passes):
                raise MorePassesRequired(len(valid_passes), required_new_passes)

        # Skip over the remotely exposed method and jump to the underlying
        # implementation which accepts one additional parameter that we know
        # about (and don't expose over the network): renew_leases.  We always
        # pass False for this because we want to manage leases completely
        # separately from writes.
        return self._original.slot_testv_and_readv_and_writev(
            storage_index,
            secrets,
            tw_vectors,
            r_vector,
            renew_leases=renew_leases,
        )

    def remote_slot_readv(self, *a, **kw):
        """
        Pass-through without a pass check to let clients read mutable shares as
        long as those shares exist.
        """
        return self._original.remote_slot_readv(*a, **kw)


def has_active_lease(storage_server, storage_index, now):
    """
    :param allmydata.storage.server.StorageServer storage_server: A storage
        server to use to look up lease information.

    :param bytes storage_index: A storage index to use to look up lease
        information.

    :param float now: The current time as a POSIX timestamp.

    :return bool: ``True`` if any only if the given storage index has a lease
        with an expiration time after ``now``.
    """
    leases = storage_server.get_slot_leases(storage_index)
    return any(
        lease.get_expiration_time() > now
        for lease
        in leases
    )


def check_pass_quantity_for_lease(storage_index, valid_passes, storage_server):
    """
    Check that the given number of passes is sufficient to add or renew a
    lease for one period for the given storage index.
    """
    allocated_sizes = dict(
        get_share_sizes(
            storage_server,
            storage_index,
            list(get_all_share_numbers(storage_server, storage_index)),
        ),
    ).values()
    # print("allocated_sizes: {}".format(allocated_sizes))
    check_pass_quantity(len(valid_passes), allocated_sizes)
    # print("Checked out")

def check_pass_quantity(valid_count, share_sizes):
    """
    Check that the given number of passes is sufficient to cover leases for
    one period for shares of the given sizes.

    :param int valid_count: The number of passes.
    :param list[int] share_sizes: The sizes of the shares for which the lease
        is being created.

    :raise MorePassesRequired: If the given number of passes is too few for
        the given share sizes.

    :return: ``None`` if the given number of passes is sufficient.
    """
    required_pass_count = required_passes(BYTES_PER_PASS, share_sizes)
    if valid_count < required_pass_count:
        raise MorePassesRequired(
            valid_count,
            required_pass_count,
        )

def check_pass_quantity_for_write(valid_count, sharenums, allocated_size):
    """
    Determine if the given number of valid passes is sufficient for an
    attempted write.

    :param int valid_count: The number of valid passes to consider.
    :param set[int] sharenums: The shares being written to.
    :param int allocated_size: The size of each share.

    :raise MorePassedRequired: If the number of valid passes given is too
        small.

    :return: ``None`` if the number of valid passes given is sufficient.
    """
    check_pass_quantity(valid_count, [allocated_size] * len(sharenums))


def get_all_share_paths(storage_server, storage_index):
    """
    Get the paths of all shares in the given storage index (or slot).

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server which owns the storage index.

    :param bytes storage_index: The storage index (or slot) in which to look
        up shares.

    :return: A generator of tuples of (int, bytes) giving a share number and
        the path to storage for that share number.
    """
    bucket = join(storage_server.sharedir, storage_index_to_dir(storage_index))
    try:
        contents = listdir(bucket)
    except OSError as e:
        if e.errno == ENOENT:
            return
        raise

    for candidate in contents:
        try:
            sharenum = int(candidate)
        except ValueError:
            pass
        else:
            yield sharenum, join(bucket, candidate)


def get_all_share_numbers(storage_server, storage_index):
    """
    Get all share numbers in the given storage index (or slot).

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server which owns the storage index.

    :param bytes storage_index: The storage index (or slot) in which to look
        up share numbers.

    :return: A generator of int giving share numbers.
    """
    for sharenum, sharepath in get_all_share_paths(storage_server, storage_index):
        yield sharenum


def get_share_sizes(storage_server, storage_index_or_slot, sharenums):
    """
    Get the sizes of the given share numbers for the given storage index *or*
    slot.

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server which owns the storage index.

    :param bytes storage_index_or_slot: The storage index (or slot) in which
        to look up share numbers.

    :param sharenums: A container of share numbers to use to filter the
        results.  Only information about share numbers in this container is
        included in the result.  Or, ``None`` to get sizes for all shares
        which exist.

    :return: A generator of tuples of (int, int) where the first element is a
        share number and the second element is the data size for that share
        number.
    """
    stat = None
    for sharenum, sharepath in get_all_share_paths(storage_server, storage_index_or_slot):
        if stat is None:
            stat = get_stat(sharepath)
        if sharenums is None or sharenum in sharenums:
            yield sharenum, stat(storage_server, storage_index_or_slot, sharepath).size


def get_storage_index_share_size(sharepath):
    """
    Get the size of a share belonging to a storage index (an immutable share).

    :param bytes sharepath: The path to the share file.

    :return int: The data size of the share in bytes.
    """
    # Note Tahoe-LAFS immutable/layout.py makes some claims about how the
    # share data is structured.  A lot of this seems to be wrong.
    # storage/immutable.py appears to have the correct information.
    fmt = ">LL"
    with open(sharepath, "rb") as share_file:
        header = share_file.read(calcsize(fmt))

    if len(header) != calcsize(fmt):
        raise ValueError(
            "Tried to read {} bytes of share file header, got {!r} instead.".format(
                calcsize(fmt),
                header,
            ),
        )

    version, share_data_length = unpack(fmt, header)
    return share_data_length


def get_lease_expiration(get_leases, storage_index_or_slot):
    """
    Get the lease expiration time for the shares in a bucket or slot, or None
    if there is no lease on them.

    :param get_leases: A one-argument callable which returns the leases.

    :param storage_index_or_slot: Either a storage index or a slot identifying
        the shares the leases of which to inspect.
    """
    for lease in get_leases(storage_index_or_slot):
        return lease.get_expiration_time()
    return None


def stat_bucket(storage_server, storage_index, sharepath):
    """
    Get a ``ShareStat`` for the shares in a bucket.
    """
    return ShareStat(
        size=get_storage_index_share_size(sharepath),
        lease_expiration=get_lease_expiration(storage_server.get_leases, storage_index),
    )


def stat_slot(storage_server, slot, sharepath):
    """
    Get a ``ShareStat`` for the shares in a slot.
    """
    return ShareStat(
        size=get_slot_share_size(sharepath),
        lease_expiration=get_lease_expiration(storage_server.get_slot_leases, slot),
    )


def get_slot_share_size(sharepath):
    """
    Get the size of a share belonging to a slot (a mutable share).

    :param bytes sharepath: The path to the share file.

    :return int: The data size of the share in bytes.
    """
    with open(sharepath, "rb") as share_file:
        share_data_length_bytes = share_file.read(92)[-8:]
        (share_data_length,) = unpack('>Q', share_data_length_bytes)
        return share_data_length


def stat_share(storage_server, storage_index_or_slot):
    """
    Get a ``ShareStat`` for each share in a bucket or a slot.

    :return: An iterator of two-tuples of share number and corresponding
        ``ShareStat``.
    """
    stat = None
    for sharenum, sharepath in get_all_share_paths(storage_server, storage_index_or_slot):
        if stat is None:
            stat = get_stat(sharepath)
        yield (sharenum, stat(storage_server, storage_index_or_slot, sharepath))


def get_stat(sharepath):
    """
    Get a function that can retrieve the metadata from the share at the given
    path.

    This is necessary to differentiate between buckets and slots.
    """
    # Figure out if it is a storage index or a slot.
    with open(sharepath, "rb") as share_file:
        magic = share_file.read(32)
        if magic == "Tahoe mutable container v1\n" + "\x75\x09\x44\x03\x8e":
            return stat_slot
        else:
            return stat_bucket


# I don't understand why this is required.
# ZKAPAuthorizerStorageServer is-a Referenceable.  It seems like
# the built in adapter should take care of this case.
from twisted.python.components import (
    registerAdapter,
)
from foolscap.referenceable import (
    ReferenceableSlicer,
)
from foolscap.ipb import (
    ISlicer,
)
registerAdapter(ReferenceableSlicer, ZKAPAuthorizerStorageServer, ISlicer)
