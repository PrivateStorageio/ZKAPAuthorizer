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

import attr

from zope.interface import (
    implementer_only,
)

from foolscap.constraint import (
    ByteStringConstraint,
)
from foolscap.api import (
    ListOf,
    Referenceable,
)
from foolscap.ipb import (
    IReferenceable,
    IRemotelyCallable,
)
from foolscap.remoteinterface import (
    RemoteMethodSchema,
    RemoteInterface,
)

from allmydata.interfaces import (
    RIStorageServer,
)

MAXIMUM_TOKENS_PER_CALL = 10
TOKEN_LENGTH = 97

Token = ByteStringConstraint(maxLength=TOKEN_LENGTH, minLength=TOKEN_LENGTH)
TokenList = ListOf(Token, maxLength=MAXIMUM_TOKENS_PER_CALL)


def add_tokens(schema):
    """
    Add a ``tokens`` parameter to the given method schema.

    :param foolscap.remoteinterface.RemoteMethodSchema schema: An existing
        method schema to modify.

    :return foolscap.remoteinterface.RemoteMethodSchema: A schema like
        ``schema`` but with one additional required argument.
    """
    return add_arguments(schema, tokens=TokenList)



def add_arguments(schema, **kwargs):
    new_kwargs = schema.argConstraints.copy()
    new_kwargs.update(kwargs)
    modified_schema = RemoteMethodSchema(**new_kwargs)
    return modified_schema



class RITokenAuthorizedStorageServer(RemoteInterface):
    __remote_name__ = (
        "RITokenAuthorizedStorageServer.tahoe.privatestorage.io"
    )

    get_version = RIStorageServer["get_version"]

    allocate_buckets = add_tokens(RIStorageServer["allocate_buckets"])

    add_lease = add_tokens(RIStorageServer["add_lease"])

    renew_lease = add_tokens(RIStorageServer["renew_lease"])

    get_buckets = RIStorageServer["get_buckets"]

    slot_readv = RIStorageServer["slot_readv"]

    slot_testv_and_readv_and_writev = add_tokens(
        RIStorageServer["slot_testv_and_readv_and_writev"],
    )

    advise_corrupt_share = RIStorageServer["advise_corrupt_share"]



@implementer_only(RITokenAuthorizedStorageServer, IReferenceable, IRemotelyCallable)
# It would be great to use `frozen=True` (value-based hashing) instead of
# `cmp=False` (identity based hashing) but Referenceable wants to set some
# attributes on self and it's hard to avoid that.
@attr.s(cmp=False)
class SecureAccessTokenAuthorizerStorageServer(Referenceable):
    _original = attr.ib()

    def _validate_tokens(self, tokens):
        pass

    def remote_allocate_buckets(self, tokens, *a, **kw):
        self._validate_tokens(tokens)
        return self._original.remote_allocate_buckets(*a, **kw)

    def remote_get_buckets(self, storage_index):
        return self._original.remote_get_buckets(storage_index)

    def remote_add_lease(self, tokens, *a, **kw):
        self._validate_tokens(tokens)
        return self._original.remote_add_lease(*a, **kw)

    def remote_renew_lease(self, tokens, *a, **kw):
        self._validate_tokens(tokens)
        return self._original.remote_renew_lease(*a, **kw)

    def remote_advise_corrupt_share(self, *a, **kw):
        return self._original.remote_advise_corrupt_share(*a, **kw)

    def remote_slot_testv_and_readv_and_writev(self, *a, **kw):
        return self._original.remote_slot_testv_and_readv_and_writev(*a, **kw)

    def remote_slot_readv(self, *a, **kw):
        return self._original.remote_slot_readv(*a, **kw)

# I don't understand why this is required.
# SecureAccessTokenAuthorizerStorageServer is-a Referenceable.  It seems like
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
registerAdapter(ReferenceableSlicer, SecureAccessTokenAuthorizerStorageServer, ISlicer)
