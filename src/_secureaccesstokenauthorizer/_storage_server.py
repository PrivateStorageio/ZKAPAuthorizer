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
from attr.validators import (
    provides,
)

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

# The Foolscap convention seems to be to try to constrain inputs to valid
# values.  So we'll try to limit the number of tokens a client can supply.
# Foolscap may be moving away from this so we may eventually drop this as
# well.  Though it may still make sense on a non-Foolscap protocol (eg HTTP)
# which Tahoe-LAFS may eventually support.
#
# In any case, for now, pick some fairly arbitrary value.  I am deliberately
# picking a small number here and expect to have to raise.  However, ideally,
# a client could accomplish a lot with a few tokens while also not wasting a
# lot of value.
MAXIMUM_TOKENS_PER_CALL = 10

# This is the length of a serialized PrivacyPass pass (there's a lot of
# confusion between "tokens" and "passes" here, sadly).
TOKEN_LENGTH = 97

# Take those values and turn them into the appropriate Foolscap constraint
# objects.  Foolscap seems to have a convention of representing these as
# CamelCase module-level values so I replicate that here.
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
    return add_arguments(schema, [(b"tokens", TokenList)])


def add_arguments(schema, kwargs):
    """
    Create a new schema like ``schema`` but with the arguments given by
    ``kwargs`` prepended to the signature.

    :param foolscap.remoteinterface.RemoteMethodSchema schema: The existing
        schema.

    :param list[(bytes, foolscap.IConstraint)] kwargs: The arguments to
        prepend to the signature of ``schema``.

    :return foolscap.remoteinterface.RemoteMethodSchema: The new schema
        object.
    """
    new_kwargs = dict(schema.argConstraints)
    new_kwargs.update(kwargs)
    modified_schema = RemoteMethodSchema(**new_kwargs)
    # Initialized from **new_kwargs, RemoteMethodSchema.argumentNames is in
    # some arbitrary, probably-incorrect order.  This breaks user code which
    # tries to use positional arguments.  Put them back in the order they were
    # in originally (in the input ``schema``), prepended with the newly added
    # arguments.
    modified_schema.argumentNames = (
        # The new arguments
        list(argName for (argName, _) in kwargs) +
        # The original arguments in the original order
        schema.argumentNames
    )
    return modified_schema



class RITokenAuthorizedStorageServer(RemoteInterface):
    """
    An object which can store and retrieve shares, subject to token-based
    authorization.

    This is much the same as ``allmydata.interfaces.RIStorageServer`` but
    several of its methods take an additional ``tokens`` parameter.  Clients
    are expected to supply suitable tokens and only after the tokens have been
    validated is service provided.
    """
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

    def remote_slot_testv_and_readv_and_writev(self, tokens, *a, **kw):
        """
        Pass through after a token check to ensure clients can only allocate
        storage for mutable shares if they present valid tokens.

        :note: This method can be used both to allocate storage and to rewrite
            data in already-allocated storage.  These cases may not be the
            same from the perspective of token validation.
        """
        self._validate_tokens(tokens)
        return self._original.remote_slot_testv_and_readv_and_writev(*a, **kw)

    def remote_slot_readv(self, *a, **kw):
        """
        Pass through without a token check to let clients read mutable shares as
        long as those shares exist.
        """
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
