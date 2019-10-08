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

from math import (
    ceil,
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
from privacypass import (
    TokenPreimage,
    VerificationSignature,
    SigningKey,
)
from .foolscap import (
    RITokenAuthorizedStorageServer,
)
from .storage_common import (
    allocate_buckets_message,
    add_lease_message,
    renew_lease_message,
    slot_testv_and_readv_and_writev_message,
)

class MorePassesRequired(Exception):
    def __init__(self, valid_count, required_count):
        self.valid_count = valid_count
        self.required_count = required_count


@implementer_only(RITokenAuthorizedStorageServer, IReferenceable, IRemotelyCallable)
# It would be great to use `frozen=True` (value-based hashing) instead of
# `cmp=False` (identity based hashing) but Referenceable wants to set some
# attributes on self and it's hard to avoid that.
@attr.s(cmp=False)
class ZKAPAuthorizerStorageServer(Referenceable):
    """
    A class which wraps an ``RIStorageServer`` to insert pass validity checks
    before allowing certain functionality.
    """
    # The number of bytes we're willing to store for a lease period for each
    # pass submitted.
    _BYTES_PER_PASS = 128 * 1024

    _original = attr.ib(validator=provides(RIStorageServer))
    _signing_key = attr.ib(validator=instance_of(SigningKey))

    def _required_passes(self, stored_bytes):
        """
        Calculate the number of passes that are required to store ``stored_bytes``
        for one lease period.

        :param int stored_bytes: A number of bytes of storage for which to
            calculate a price in passes.

        :return int: The number of passes.
        """
        return int(ceil(stored_bytes / self._BYTES_PER_PASS))

    def _is_invalid_pass(self, message, pass_):
        """
        Check the validity of a single pass.

        :param unicode message: The shared message for pass validation.
        :param bytes pass_: The encoded pass to validate.

        :return bool: ``True`` if the pass is invalid, ``False`` otherwise.
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
        return list(
            pass_
            for pass_
            in passes
            if not self._is_invalid_pass(message, pass_)
        )

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
        required_passes = self._required_passes(len(sharenums) * allocated_size)
        if len(valid_passes) < required_passes:
            raise MorePassesRequired(
                len(valid_passes),
                required_passes,
            )

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
        self._validate_passes(add_lease_message(storage_index), passes)
        return self._original.remote_add_lease(storage_index, *a, **kw)

    def remote_renew_lease(self, passes, storage_index, *a, **kw):
        """
        Pass-through after a pass check to ensure clients can only extend the
        duration of share storage if they present valid passes.
        """
        self._validate_passes(renew_lease_message(storage_index), passes)
        return self._original.remote_renew_lease(storage_index, *a, **kw)

    def remote_advise_corrupt_share(self, *a, **kw):
        """
        Pass-through without a pass check to let clients inform us of possible
        issues with the system without incurring any cost to themselves.
        """
        return self._original.remote_advise_corrupt_share(*a, **kw)

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
        self._validate_passes(slot_testv_and_readv_and_writev_message(storage_index), passes)
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
            renew_leases=False,
        )

    def remote_slot_readv(self, *a, **kw):
        """
        Pass-through without a pass check to let clients read mutable shares as
        long as those shares exist.
        """
        return self._original.remote_slot_readv(*a, **kw)

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
