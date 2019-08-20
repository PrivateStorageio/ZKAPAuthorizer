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
updates using a per-call token.

This is the server part of a storage access protocol.  The client part is
implemented in ``_storage_client.py``.
"""

from __future__ import (
    absolute_import,
)

import attr
from attr.validators import (
    provides,
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

from .foolscap import (
    RITokenAuthorizedStorageServer,
)

@implementer_only(RITokenAuthorizedStorageServer, IReferenceable, IRemotelyCallable)
# It would be great to use `frozen=True` (value-based hashing) instead of
# `cmp=False` (identity based hashing) but Referenceable wants to set some
# attributes on self and it's hard to avoid that.
@attr.s(cmp=False)
class ZKAPAuthorizerStorageServer(Referenceable):
    """
    A class which wraps an ``RIStorageServer`` to insert token validity checks
    before allowing certain functionality.
    """
    _original = attr.ib(validator=provides(RIStorageServer))

    def _validate_tokens(self, tokens):
        """
        Check that all of the given tokens are valid.

        :raise InvalidToken: If any token in ``tokens`` is not valid.

        :return NoneType: If all of the tokens in ``tokens`` are valid.

        :note: This is yet to be implemented so it always returns ``None``.
        """
        return None

    def remote_get_version(self):
        """
        Pass through without token check to allow clients to learn about our
        version and configuration in case it helps them decide how to behave.
        """
        return self._original.remote_get_version()

    def remote_allocate_buckets(self, tokens, *a, **kw):
        """
        Pass through after a token check to ensure that clients can only allocate
        storage for immutable shares if they present valid tokens.
        """
        self._validate_tokens(tokens)
        return self._original.remote_allocate_buckets(*a, **kw)

    def remote_get_buckets(self, storage_index):
        """
        Pass through without token check to let clients read immutable shares as
        long as those shares exist.
        """
        return self._original.remote_get_buckets(storage_index)

    def remote_add_lease(self, tokens, *a, **kw):
        """
        Pass through after a token check to ensure clients can only extend the
        duration of share storage if they present valid tokens.
        """
        self._validate_tokens(tokens)
        return self._original.remote_add_lease(*a, **kw)

    def remote_renew_lease(self, tokens, *a, **kw):
        """
        Pass through after a token check to ensure clients can only extend the
        duration of share storage if they present valid tokens.
        """
        self._validate_tokens(tokens)
        return self._original.remote_renew_lease(*a, **kw)

    def remote_advise_corrupt_share(self, *a, **kw):
        """
        Pass through without a token check to let clients inform us of possible
        issues with the system without incurring any cost to themselves.
        """
        return self._original.remote_advise_corrupt_share(*a, **kw)

    def remote_slot_testv_and_readv_and_writev(
            self,
            tokens,
            storage_index,
            secrets,
            tw_vectors,
            r_vector,
    ):
        """
        Pass through after a token check to ensure clients can only allocate
        storage for mutable shares if they present valid tokens.

        :note: This method can be used both to allocate storage and to rewrite
            data in already-allocated storage.  These cases may not be the
            same from the perspective of token validation.
        """
        self._validate_tokens(tokens)
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
        Pass through without a token check to let clients read mutable shares as
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
