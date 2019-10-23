from __future__ import (
    absolute_import,
)

from foolscap.constraint import (
    ByteStringConstraint,
)
from foolscap.api import (
    Any,
    DictOf,
    ListOf,
)
from foolscap.remoteinterface import (
    RemoteMethodSchema,
    RemoteInterface,
)

from allmydata.interfaces import (
    StorageIndex,
    RIStorageServer,
    Offset,
)

# The Foolscap convention seems to be to try to constrain inputs to valid
# values.  So we'll try to limit the number of passes a client can supply.
# Foolscap may be moving away from this so we may eventually drop this as
# well.  Though it may still make sense on a non-Foolscap protocol (eg HTTP)
# which Tahoe-LAFS may eventually support.
#
# If a pass is worth 128 KiB of storage for some amount of time, 2 ** 20
# passes is worth 128 GiB of storage for some amount of time.  It is an
# arbitrary upper limit on the size of immutable files but maybe it's large
# enough to not be an issue for a while.
#
# The argument for having a limit here at all is protection against denial of
# service attacks that exhaust server memory but creating unbearably large
# lists.
#
# A limit of 2 ** 20 passes translates to 177 MiB (times some constant factor
# for Foolscap/Python overhead).  That should be tolerable.
_MAXIMUM_PASSES_PER_CALL = 2 ** 20

# This is the length of a serialized Ristretto-flavored PrivacyPass pass The
# pass is a combination of token preimages and unblinded token signatures,
# each base64-encoded.
_PASS_LENGTH = 177

# Take those values and turn them into the appropriate Foolscap constraint
# objects.  Foolscap seems to have a convention of representing these as
# CamelCase module-level values so I replicate that here.
_Pass = ByteStringConstraint(maxLength=_PASS_LENGTH, minLength=_PASS_LENGTH)
_PassList = ListOf(_Pass, maxLength=_MAXIMUM_PASSES_PER_CALL)


def add_passes(schema):
    """
    Add a ``passes`` parameter to the given method schema.

    :param foolscap.remoteinterface.RemoteMethodSchema schema: An existing
        method schema to modify.

    :return foolscap.remoteinterface.RemoteMethodSchema: A schema like
        ``schema`` but with one additional required argument.
    """
    return add_arguments(schema, [(b"passes", _PassList)])


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



class RIPrivacyPassAuthorizedStorageServer(RemoteInterface):
    """
    An object which can store and retrieve shares, subject to pass-based
    authorization.

    This is much the same as ``allmydata.interfaces.RIStorageServer`` but
    several of its methods take an additional ``passes`` parameter.  Clients
    are expected to supply suitable passes and only after the passes have been
    validated is service provided.
    """
    __remote_name__ = (
        "RIPrivacyPassAuthorizedStorageServer.tahoe.privatestorage.io"
    )

    get_version = RIStorageServer["get_version"]

    allocate_buckets = add_passes(RIStorageServer["allocate_buckets"])

    add_lease = add_passes(RIStorageServer["add_lease"])

    renew_lease = add_passes(RIStorageServer["renew_lease"])

    get_buckets = RIStorageServer["get_buckets"]

    def share_sizes(
            storage_index_or_slot=StorageIndex,
            # Notionally, ChoiceOf(None, SetOf(int, maxLength=MAX_BUCKETS)).
            # However, support for such a construction appears to be
            # unimplemented in Foolscap.  So, instead...
            sharenums=Any(),
    ):
        """
        Get the size of the given shares in the given storage index or slot.  If a
        share has no stored state, its size is reported as 0.
        """
        return DictOf(int, Offset)

    slot_readv = RIStorageServer["slot_readv"]

    slot_testv_and_readv_and_writev = add_passes(
        RIStorageServer["slot_testv_and_readv_and_writev"],
    )

    advise_corrupt_share = RIStorageServer["advise_corrupt_share"]
