# -*- coding: utf-8 -*-
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

from datetime import timedelta
from errno import ENOENT
from functools import partial
from os import listdir, stat
from os.path import join
from struct import calcsize, unpack
from typing import Any, Optional

import attr
from allmydata.interfaces import TestAndWriteVectorsForShares
from allmydata.storage.common import storage_index_to_dir
from allmydata.storage.immutable import (
    BucketWriter,
    FoolscapBucketReader,
    FoolscapBucketWriter,
    ShareFile,
)
from allmydata.storage.lease import LeaseInfo
from allmydata.storage.mutable import MutableShareFile
from allmydata.storage.server import StorageServer
from allmydata.storage.shares import get_share_file
from allmydata.util.base32 import b2a
from attr.validators import instance_of, provides
from attrs import frozen
from challenge_bypass_ristretto import (
    PublicKey,
    SigningKey,
    TokenPreimage,
    VerificationSignature,
)
from eliot import log_call, start_action
from foolscap.api import Referenceable
from foolscap.ipb import IRemoteReference
from prometheus_client import CollectorRegistry, Histogram
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTime
from twisted.python.filepath import FilePath
from twisted.python.reflect import namedAny
from zope.interface import implementer

from .foolscap import RIPrivacyPassAuthorizedStorageServer, ShareStat
from .model import Pass
from .server.spending import ISpender
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

# See allmydata/storage/mutable.py
SLOT_HEADER_SIZE = 468
LEASE_TRAILER_SIZE = 4


class NewLengthRejected(Exception):
    """
    A non-None value for ``new_length`` was given to
    ``slot_testv_and_readv_and_writev``.

    This is disallowed by ZKAPAuthorizer because of the undesirable
    interactions with the current spending protocol and because there are no
    known real-world use-cases for this usage.
    """


@frozen
class _ValidationResult(object):
    """
    The result of validating a list of passes.

    :ivar valid: A list of valid token preimages.

    :ivar signature_check_failed: A list of indexes (into the validated list)
        of passes which did not have a correct signature.
    """

    valid: list[bytes]
    signature_check_failed: list[int]

    @classmethod
    def _is_invalid_pass(cls, message, pass_, signing_key):
        """
        Cryptographically check the validity of a single pass.

        :param bytes message: The shared message for pass validation.
        :param Pass pass_: The pass to validate.

        :return bool: ``False`` (invalid) if the pass includes a valid
            signature, ``True`` (valid) otherwise.
        """
        assert isinstance(message, bytes), "message %r not bytes" % (message,)
        assert isinstance(pass_, Pass), "pass %r not a Pass" % (pass_,)
        try:
            preimage = TokenPreimage.decode_base64(pass_.preimage)
            proposed_signature = VerificationSignature.decode_base64(pass_.signature)
            unblinded_token = signing_key.rederive_unblinded_token(preimage)
            verification_key = unblinded_token.derive_verification_key_sha512()
            invalid_pass = verification_key.invalid_sha512(
                proposed_signature,
                message,
            )
            return invalid_pass
        except Exception:
            # It would be pretty nice to log something here, sometimes, I guess?
            return True

    @classmethod
    def validate_passes(cls, message, passes, signing_key):
        """
        Check all of the given passes for validity.

        :param bytes message: The shared message for pass validation.
        :param list[bytes] passes: The encoded passes to validate.
        :param SigningKey signing_key: The signing key to use to check the passes.

        :return: An instance of this class describing the validation result
            for all passes given.
        """
        valid = []
        signature_check_failed = []
        for idx, pass_ in enumerate(passes):
            pass_ = Pass.from_bytes(pass_)
            if cls._is_invalid_pass(message, pass_, signing_key):
                signature_check_failed.append(idx)
            else:
                valid.append(pass_.preimage)
        return cls(
            valid=valid,
            signature_check_failed=signature_check_failed,
        )

    def raise_for(self, required_pass_count):
        """
        :raise MorePassesRequired: Always raised with fields populated from this
            instance and the given ``required_pass_count``.
        """
        raise MorePassesRequired(
            len(self.valid),
            required_pass_count,
            self.signature_check_failed,
        )


class LeaseRenewalRequired(Exception):
    """
    Mutable write operations fail with ``LeaseRenewalRequired`` when the slot
    which is the target of the write does not have an active lease and no
    passes are supplied to create one.
    """


@implementer(
    RIPrivacyPassAuthorizedStorageServer  # type: ignore # zope.interface.implementer accepts interface, not ...
)
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

    # A StorageServer instance, but not validated because of the fake used in
    # the test suite.
    _original = attr.ib()

    _pass_value = pass_value_attribute()
    _signing_key = attr.ib(validator=instance_of(SigningKey))
    _spender = attr.ib(validator=provides(ISpender))
    _registry = attr.ib(
        default=attr.Factory(CollectorRegistry),
        validator=attr.validators.instance_of(CollectorRegistry),
    )
    _clock = attr.ib(
        validator=provides(IReactorTime),
        default=attr.Factory(partial(namedAny, "twisted.internet.reactor")),
    )
    _public_key = attr.ib(init=False)
    _metric_spending_successes = attr.ib(init=False)
    _bucket_writer_disconnect_markers: dict[
        BucketWriter, tuple[IRemoteReference, Any]
    ] = attr.ib(
        init=False,
        default=attr.Factory(dict),
    )

    @_public_key.default
    def _get_public_key(self):
        # attrs evaluates defaults (whether specified inline or via decorator)
        # in the order the attributes were defined in the class definition,
        # so that `self._signing_key` will be assigned when this runs.
        return PublicKey.from_signing_key(self._signing_key)

    def _bucket_writer_closed(self, bw: BucketWriter):
        """
        This is registered as a callback with the storage backend and receives
        notification when a bucket writer is closed.  It removes the
        disconnection-based cleanup callback for the given bucket.
        """
        # This implementation was originally copied from
        # allmydata.storage.server.FoolscapStorageServer.  Since we don't use
        # Tahoe's Foolscap storage server layer we need to do this bucket
        # writer bookkeeping ourselves.
        if bw in self._bucket_writer_disconnect_markers:
            canary, disconnect_marker = self._bucket_writer_disconnect_markers.pop(bw)
            canary.dontNotifyOnDisconnect(disconnect_marker)

    def __attrs_post_init__(self):
        """
        Finish initialization after attrs does its job.  This consists of
        registering a cleanup handler with the storage backend.
        """
        self._original.register_bucket_writer_close_handler(self._bucket_writer_closed)

    def _get_spending_histogram_buckets(self):
        """
        Create the upper bounds for the ZKAP spending histogram.
        """
        # We want a lot of small buckets to be able to get an idea of how much
        # spending is for tiny files where our billing system doesn't work
        # extremely well.  We also want some large buckets so we have a point
        # of comparison - is there a lot more or less spending on big files
        # than small files?  Prometheus recommends a metric have a maximum
        # cardinality below 10
        # (<https://prometheus.io/docs/practices/instrumentation/#do-not-overuse-labels>).
        # Histograms are implemented with labels so the cardinality is equal
        # to the number of buckets.  We will push this a little bit so we can
        # span a better range.  The good news is that this is a static
        # cardinality (it does not change based on the data observed) so we
        # are not at risk of blowing up the metrics overhead unboundedly.  11
        # finite buckets + 1 infinite bucket covers 1 to 1024 ZKAPs (plus
        # infinity) and only needs 12 buckets.
        return list(2**n for n in range(11)) + [float("inf")]

    @_metric_spending_successes.default
    def _make_histogram(self):
        return Histogram(
            "zkapauthorizer_server_spending_successes",
            "ZKAP Spending Successes histogram",
            registry=self._registry,
            buckets=self._get_spending_histogram_buckets(),
        )

    def _clear_metrics(self):
        """
        Forget all recorded metrics.
        """
        # There is also a `clear` method it's for something else.  See
        # https://github.com/prometheus/client_python/issues/707
        self._metric_spending_successes._metric_init()

    def remote_get_version(self):
        """
        Pass-through without pass check to allow clients to learn about our
        version and configuration in case it helps them decide how to behave.
        """
        return self._original.get_version()

    def remote_allocate_buckets(
        self,
        passes,
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        allocated_size,
        canary,
    ):
        """
        Pass-through after a pass check to ensure that clients can only allocate
        storage for immutable shares if they present valid passes.
        """
        validation = _ValidationResult.validate_passes(
            allocate_buckets_message(storage_index),
            passes,
            self._signing_key,
        )

        # Note: The *allocate_buckets* protocol allows for some shares to
        # already exist on the server.  When this is the case, the cost of the
        # operation is based only on the shares which are really allocated
        # here.  It's not clear if we can allow the client to supply the
        # reduced number of passes in the call but we can be sure to only mark
        # as spent enough passes to cover the allocated buckets.  The return
        # value of the method will tell the client what the true cost was and
        # they can update their books in the same way.
        #
        # "Spending" isn't implemented yet so there is no code here to deal
        # with this fact (though the client does do the necessary bookkeeping
        # already).  See
        # https://github.com/PrivateStorageio/ZKAPAuthorizer/issues/41.
        #
        # Note: The downside of this scheme is that the client has revealed
        # some tokens to us.  If we act in bad faith we can use this
        # information to correlate this operation with a future operation
        # where they are re-spent.  We don't do this but it would be better if
        # we fixed the protocol so it's not even possible.  Probably should
        # file a ticket for this.
        check_pass_quantity_for_write(
            self._pass_value,
            validation,
            sharenums,
            allocated_size,
        )

        alreadygot, bucketwriters = self._original.allocate_buckets(
            storage_index,
            renew_secret,
            cancel_secret,
            sharenums,
            allocated_size,
            renew_leases=False,
        )

        # We just committed to spending some of the presented passes.  If
        # `alreadygot` is not empty then we didn't commit to spending *all* of
        # them.  (Also, we didn't *accept* data for storage yet - but that's a
        # defect in the spending protocol and metrics can't fix it so just
        # ignore that for now.)
        #
        # This expression mirrors the expression the client uses to determine
        # how many passes were spent when it processes the result we return to
        # it.
        spent_passes = required_passes(
            self._pass_value,
            [allocated_size] * len(bucketwriters),
        )
        self._metric_spending_successes.observe(spent_passes)

        # Copy/paste the disconnection handling logic from
        # StorageServer.remote_allocate_buckets.
        for bw in bucketwriters.values():
            disconnect_marker = canary.notifyOnDisconnect(bw.disconnected)
            self._bucket_writer_disconnect_markers[bw] = (
                canary,
                disconnect_marker,
            )
        self._spender.mark_as_spent(
            self._public_key,
            validation.valid[:spent_passes],
        )
        return alreadygot, {
            k: FoolscapBucketWriter(bw) for (k, bw) in bucketwriters.items()
        }

    def remote_get_buckets(self, storage_index):
        """
        Pass-through without pass check to let clients read immutable shares as
        long as those shares exist.
        """
        return {
            k: FoolscapBucketReader(bucket)
            for (k, bucket) in self._original.get_buckets(storage_index).items()
        }

    def remote_add_lease(self, passes, storage_index, *a, **kw):
        """
        Pass-through after a pass check to ensure clients can only extend the
        duration of share storage if they present valid passes.
        """
        validation = _ValidationResult.validate_passes(
            add_lease_message(storage_index),
            passes,
            self._signing_key,
        )
        check_pass_quantity_for_lease(
            self._pass_value,
            storage_index,
            validation,
            self._original,
        )
        result = self._original.add_lease(storage_index, *a, **kw)
        self._spender.mark_as_spent(
            self._public_key,
            validation.valid,
        )
        self._metric_spending_successes.observe(len(validation.valid))
        return result

    def remote_advise_corrupt_share(self, *a, **kw):
        """
        Pass-through without a pass check to let clients inform us of possible
        issues with the system without incurring any cost to themselves.
        """
        return self._original.advise_corrupt_share(*a, **kw)

    def remote_share_sizes(self, storage_index_or_slot, sharenums):
        with start_action(
            action_type="zkapauthorizer:storage-server:remote:share-sizes",
            storage_index_or_slot=storage_index_or_slot,
        ):
            return dict(
                get_share_sizes(self._original, storage_index_or_slot, sharenums)
            )

    def remote_stat_shares(
        self, storage_indexes_or_slots: list[bytes]
    ) -> list[dict[int, ShareStat]]:
        return list(
            dict(get_share_stats(self._original, storage_index_or_slot, None))
            for storage_index_or_slot in storage_indexes_or_slots
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
        Perform a test-and-set on a number of shares in a given slot.

        Optionally, also read some data to be returned before writing any
        changes.

        If storage-time will be allocated by the operation then validate the
        given passes and ensure they are of sufficient quantity to pay for the
        allocation.

        Specifically, passes are required in the following cases:

        * If shares are created then a lease is added to them.
          Passes are required for the full size of the share.

        * If shares without unexpired leases are written then a lease is added to them.
          Passes are required for the full size of the shares after the write.

        * If shares with unexpired leases are made larger.
          Passes are required for the difference in price between the old and new size.
          Note that the lease is *not* renewed in this case (see #254).
        """
        with start_action(
            action_type="zkapauthorizer:storage-server:remote:slot-testv-and-readv-and-writev",
            storage_index=b2a(storage_index),
            path=storage_index_to_dir(storage_index),
        ):
            result = self._slot_testv_and_readv_and_writev(
                passes,
                storage_index,
                secrets,
                tw_vectors,
                r_vector,
            )
            if isinstance(result, Deferred):
                raise TypeError("_slot_testv_and_readv_and_writev returned Deferred")
            return result

    def _slot_testv_and_readv_and_writev(
        self,
        passes,
        storage_index,
        secrets,
        tw_vectors,
        r_vector,
    ):
        # Get a stable time to use for all lease expiration checks that are
        # part of this call.
        now = self._clock.seconds()

        # We're not exactly sure what to do with mutable container truncations
        # and the official client doesn't ever use that feature so just
        # disable it by rejecting all attempts here.
        for (testv, writev, new_length) in tw_vectors.values():
            if new_length is not None:
                raise NewLengthRejected(new_length)

        # Check passes for cryptographic validity.
        validation = _ValidationResult.validate_passes(
            slot_testv_and_readv_and_writev_message(storage_index),
            passes,
            self._signing_key,
        )

        # Inspect the operation to determine its price based on any
        # allocations.
        required_new_passes = get_writev_price(
            self._original,
            self._pass_value,
            storage_index,
            tw_vectors,
            now,
        )

        # Fail the operation right now if there aren't enough valid passes to
        # cover the price.
        if required_new_passes > len(validation.valid):
            validation.raise_for(required_new_passes)

        # Perform the operation.
        result = self._original.slot_testv_and_readv_and_writev(
            storage_index,
            secrets,
            tw_vectors,
            r_vector,
            # Disable all lease renewal logic from the wrapped storage server.
            # We'll add or renew leases based on our billing model.
            renew_leases=False,
        )

        # Add the leases that we charged the client for.  This includes:
        #
        #  - leases on newly created shares
        #
        #  - leases on existing, modified shares without an unexpired lease
        #
        # Note it does not include existing shares that grew enough to be more
        # expensive.  The operation was required to pay the full price
        # difference but this only grants storage for the remainder of the
        # existing lease period.  This results in the client being overcharged
        # somewhat.
        add_leases_for_writev(self._original, storage_index, secrets, tw_vectors, now)

        self._spender.mark_as_spent(
            self._public_key,
            validation.valid,
        )

        # The operation has fully succeeded.
        self._metric_spending_successes.observe(required_new_passes)

        # Propagate the result of the operation.
        return result

    def remote_slot_readv(self, *a, **kw):
        """
        Pass-through without a pass check to let clients read mutable shares as
        long as those shares exist.
        """
        return self._original.slot_readv(*a, **kw)


def check_pass_quantity(pass_value, validation, share_sizes):
    """
    Check that the given number of passes is sufficient to cover leases for
    one period for shares of the given sizes.

    :param int pass_value: The value of a single pass in bytes × lease periods.

    :param _ValidationResult validation: The validating results for a list of passes.

    :param list[int] share_sizes: The sizes of the shares for which the lease
        is being created.

    :raise MorePassesRequired: If the given number of passes is too few for
        the given share sizes.

    :return: ``None`` if the given number of passes is sufficient.
    """
    required_pass_count = required_passes(pass_value, share_sizes)
    if len(validation.valid) < required_pass_count:
        validation.raise_for(required_pass_count)


def check_pass_quantity_for_lease(
    pass_value: int,
    storage_index: bytes,
    validation: _ValidationResult,
    storage_server: ZKAPAuthorizerStorageServer,
) -> dict[int, int]:
    """
    Check that the given number of passes is sufficient to add or renew a
    lease for one period for the given storage index.

    :param int pass_value: The value of a single pass in bytes × lease periods.

    :param _ValidationResult validation: The validating results for a list of passes.

    :raise MorePassesRequired: If the given number of passes is too few for
        the share sizes at the given storage index.

    :return: A mapping from share number to share size on the server if the
        number of passes given is sufficient.
    """
    allocated_sizes = dict(
        get_share_sizes(
            storage_server,
            storage_index,
            list(get_all_share_numbers(storage_server, storage_index)),
        ),
    )
    check_pass_quantity(pass_value, validation, allocated_sizes.values())
    return allocated_sizes


def check_pass_quantity_for_write(pass_value, validation, sharenums, allocated_size):
    """
    Determine if the given number of valid passes is sufficient for an
    attempted write.

    :param int pass_value: The value of a single pass in bytes × lease periods.

    :param _ValidationResult validation: The validating results for a list of passes.

    :param set[int] sharenums: The shares being written to.

    :param int allocated_size: The size of each share.

    :raise MorePassedRequired: If the number of valid passes given is too
        small.

    :return: ``None`` if the number of valid passes given is sufficient.
    """
    check_pass_quantity(pass_value, validation, [allocated_size] * len(sharenums))


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


@log_call(
    action_type="zkapauthorizer:storage-server:get-share-sizes",
    include_args=["storage_index_or_slot", "sharenums"],
)
def get_share_sizes(storage_server, storage_index_or_slot, sharenums):
    """
    Get sizes of the given share numbers for the given storage index *or*
    slot.

    :see: ``get_share_stats``

    :return: A list of tuples of (int, int) where the first element is a share
        number and the second element is the data size for that share number.
    """
    return list(
        (sharenum, stat.size)
        for (sharenum, stat) in get_share_stats(
            storage_server, storage_index_or_slot, sharenums
        )
    )


def get_share_stats(storage_server, storage_index_or_slot, sharenums):
    """
    Get the stats for the given share numbers for the given storage index *or*
    slot.

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server which owns the storage index.

    :param bytes storage_index_or_slot: The storage index (or slot) in which
        to look up share numbers.

    :param sharenums: A container of share numbers to use to filter the
        results.  Only information about share numbers in this container is
        included in the result.  Or, ``None`` to get sizes for all shares
        which exist.

    :return: A generator of tuples of (int, ShareStat) where the first element
        is a share number and the second element gives stats about that share.
    """
    stat = None
    for sharenum, sharepath in get_all_share_paths(
        storage_server, storage_index_or_slot
    ):
        if stat is None:
            stat = get_stat(sharepath)
        if sharenums is None or sharenum in sharenums:
            info = stat(storage_server, storage_index_or_slot, sharepath)
            yield sharenum, info


def get_storage_index_share_size(sharepath):
    """
    Get the size of a share belonging to a storage index (an immutable share).

    :param bytes sharepath: The path to the share file.

    :return int: The data size of the share in bytes.
    """
    # From src/allmydata/storage/immutable.py
    #
    # The share file has the following layout:
    #  0x00: share file version number, four bytes, current version is 2
    #  0x04: share data length, four bytes big-endian = A # See Footnote 1 below.
    #  0x08: number of leases, four bytes big-endian
    #  0x0c: beginning of share data (see immutable.layout.WriteBucketProxy)
    #  A+0x0c = B: first lease. Lease format is:
    #   B+0x00: owner number, 4 bytes big-endian, 0 is reserved for no-owner
    #   B+0x04: renew secret, 32 bytes (SHA256)
    #   B+0x24: cancel secret, 32 bytes (SHA256)
    #   B+0x44: expiration time, 4 bytes big-endian seconds-since-epoch
    #   B+0x48: next lease, or end of record
    #
    # Footnote 1: as of Tahoe v1.3.0 this field is not used by storage
    # servers, but it is still filled in by storage servers in case the
    # storage server software gets downgraded from >= Tahoe v1.3.0 to < Tahoe
    # v1.3.0, or the share file is moved from one storage server to
    # another. The value stored in this field is truncated, so if the actual
    # share data length is >= 2**32, then the value stored in this field will
    # be the actual share data length modulo 2**32.

    share_file_size = stat(sharepath).st_size
    header_format = ">LLL"
    header_size = calcsize(header_format)
    with open(sharepath, "rb") as share_file:
        header = share_file.read(calcsize(header_format))

    if len(header) != header_size:
        raise ValueError(
            "Tried to read {} bytes of share file header, got {!r} instead.".format(
                calcsize(header_format),
                header,
            ),
        )

    version, _, number_of_leases = unpack(header_format, header)

    if version in (1, 2):
        # Version 1 and 2 don't differ in a way that changes the size
        # calculation.
        return share_file_size - header_size - (number_of_leases * (4 + 32 + 32 + 4))

    raise ValueError(
        "Cannot interpret version {} share file.".format(version),
    )


def stat_bucket(storage_server, storage_index, sharepath):
    """
    Get a ``ShareStat`` for the shares in a bucket.
    """
    return ShareStat(
        size=get_storage_index_share_size(sharepath),
        lease_expiration=get_lease_expiration(sharepath),
    )


def stat_slot(storage_server, slot, sharepath):
    """
    Get a ``ShareStat`` for the shares in a slot.
    """
    return ShareStat(
        size=get_slot_share_size(sharepath),
        lease_expiration=get_lease_expiration(sharepath),
    )


def get_lease_expiration(sharepath: str) -> Optional[int]:
    """
    Get the latest lease expiration time for the share at the given path, or
    ``None`` if there are no leases on it.

    :param sharepath: The path to the share file to inspect.
    """
    leases = list(
        lease.get_expiration_time() for lease in get_share_file(sharepath).get_leases()
    )
    if leases:
        return max(leases)
    return None


def get_slot_share_size(sharepath):
    """
    Get the size of a share belonging to a slot (a mutable share).

    :param bytes sharepath: The path to the share file.

    :return int: The data size of the share in bytes.
    """
    with open(sharepath, "rb") as share_file:
        share_data_length_bytes = share_file.read(92)[-8:]
        (share_data_length,) = unpack(">Q", share_data_length_bytes)
        return share_data_length


def get_stat(sharepath):
    """
    Get a function that can retrieve the metadata from the share at the given
    path.

    This is necessary to differentiate between buckets and slots.
    """
    # Figure out if it is a storage index or a slot.
    with open(sharepath, "rb") as share_file:
        magic = share_file.read(32)
        if len(magic) < 32:
            # Tahoe could check for this.
            # https://tahoe-lafs.org/trac/tahoe-lafs/ticket/3853
            raise ValueError("Share file has short header")
        if ShareFile.is_valid_header(magic):
            return stat_bucket
        elif MutableShareFile.is_valid_header(magic):
            return stat_slot
        else:
            raise ValueError("Cannot interpret share header {!r}".format(magic))


def add_leases_for_writev(storage_server, storage_index, secrets, tw_vectors, now):
    """
    Add a new lease using the given secrets to all shares written by
    ``tw_vectors``.
    """
    for (sharenum, sharepath) in get_all_share_paths(storage_server, storage_index):
        testv, datav, new_length = tw_vectors.get(sharenum, (None, b"", None))
        if datav or (new_length is not None):
            # It has data or a new length - it is a write.
            if share_has_active_leases(storage_server, storage_index, sharenum, now):
                # It's fine, leave it be.
                continue

            # Aha.  It has no lease that hasn't expired.  Give it one.
            (write_enabler, renew_secret, cancel_secret) = secrets
            share = get_share_file(sharepath)
            share.add_or_renew_lease(
                storage_server.get_available_space(),
                LeaseInfo(
                    owner_num=1,
                    renew_secret=renew_secret,
                    cancel_secret=cancel_secret,
                    expiration_time=now
                    + ZKAPAuthorizerStorageServer.LEASE_PERIOD.total_seconds(),
                    nodeid=storage_server.my_nodeid,
                ),
            )


def get_share_path(
    storage_server: StorageServer, storage_index: bytes, sharenum: int
) -> FilePath:
    """
    Get the path to the given storage server's storage for the given share.
    """
    return (
        FilePath(storage_server.sharedir)
        .preauthChild(storage_index_to_dir(storage_index))
        .child("{}".format(sharenum))
    )


def share_has_active_leases(
    storage_server: StorageServer, storage_index: bytes, sharenum: int, now: float
) -> bool:
    """
    Determine whether the given share on the given server has an unexpired
    lease or not.

    :return: ``True`` if it has at least one unexpired lease, ``False``
        otherwise.
    """
    sharepath = get_share_path(storage_server, storage_index, sharenum)
    share = get_share_file(sharepath.path)
    return any(lease.get_expiration_time() > now for lease in share.get_leases())


def get_writev_price(
    storage_server: StorageServer,
    pass_value: int,
    storage_index: bytes,
    tw_vectors: TestAndWriteVectorsForShares,
    now: float,
) -> int:
    """
    Determine the price to execute the given test/write vectors.
    """
    # Find the current size of shares being written.
    current_sizes = dict(
        get_share_sizes(
            storage_server,
            storage_index,
            # Here's how we restrict the result to only written shares.
            sharenums=get_write_sharenums(tw_vectors),
        ),
    )

    # Zero out the size of any share without an unexpired lease.  We will
    # renew the lease on this share along with the write but the client
    # must supply the necessary passes to do so.
    current_sizes.update(
        {
            sharenum: 0
            for sharenum in current_sizes
            if not share_has_active_leases(
                storage_server,
                storage_index,
                sharenum,
                now,
            )
        }
    )

    # Compute the number of passes required to execute the given writev
    # against these existing shares.
    return get_required_new_passes_for_mutable_write(
        pass_value,
        current_sizes,
        tw_vectors,
    )
