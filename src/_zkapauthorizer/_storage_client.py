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
from typing import Any, Awaitable, Callable, Optional, Protocol, TypeVar

from allmydata.interfaces import IStorageServer
from attrs import Factory, define, field
from foolscap.ipb import IRemoteReference
from foolscap.referenceable import RemoteReference
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTime
from twisted.python.reflect import namedAny
from typing_extensions import Concatenate, ParamSpec
from zope.interface import implementer

from ._attrs_zope import provides
from .eliot import CALL_WITH_PASSES, SIGNATURE_CHECK_FAILED, log_call_coroutine
from .foolscap import ShareStat
from .spending import IPassGroup
from .storage_common import (
    ClientTestWriteVector,
    MorePassesRequired,
    ReadVector,
    Secrets,
    ServerTestWriteVector,
    add_lease_message,
    allocate_buckets_message,
    get_required_new_passes_for_mutable_write,
    get_write_sharenums,
    required_passes,
    slot_testv_and_readv_and_writev_message,
)
from .validators import positive_integer

_T = TypeVar("_T")
_P = ParamSpec("_P")


@define(auto_exc=False, str=True)
class IncorrectStorageServerReference(Exception):
    """
    A Foolscap remote object which should reference a ZKAPAuthorizer storage
    server instead references some other kind of object.  This makes the
    connection, and thus the configured storage server, unusable.
    """

    furl: str
    actual_name: str
    expected_name: str


def invalidate_rejected_passes(
    passes: IPassGroup, more_passes_required: MorePassesRequired
) -> Optional[IPassGroup]:
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


async def call_with_passes_with_manual_spend(
    method: Callable[[IPassGroup], Awaitable[_T]],
    num_passes: int,
    get_passes: Callable[[int], IPassGroup],
    on_success: Callable[[_T, IPassGroup], None],
) -> _T:
    """
    Call a method, passing the requested number of passes as the first
    argument, and try again if the call fails with an error related to some of
    the passes being rejected.

    :param method: An operation to call with some passes.  If the returned
        awaitable raises ``MorePassesRequired`` then the invalid passes will
        be discarded and replacement passes will be requested for a new call
        of ``method``.  This will repeat until no passes remain, the method
        succeeds, or the methods fails in a different way.

    :param num_passes: The number of passes to pass to the call.

    :param get_passes: A function for getting passes.

    :param on_success: A function to call when ``method`` succeeds.  The first
        argument is the result of ``method``.  The second argument is the
        ``IPassGroup`` used with the successful call.  The intended purpose of
        this hook is to mark as spent passes in the group which the method has
        spent.  This is useful if the result of ``method`` can be used to
        determine the operation had a lower cost than the worst-case expected
        from its inputs.

        Spent passes should be marked as spent.  All others should be reset.

    :return: The result of ``method`` call.

    :raise: Anything raised by ``method`` except for ``MorePassesRequired``.
    """
    with CALL_WITH_PASSES(count=num_passes):
        pass_group = get_passes(num_passes)
        try:
            # Try and repeat as necessary.
            while True:
                try:
                    result = await method(pass_group)
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
    return result


async def call_with_passes(
    method: Callable[[IPassGroup], Awaitable[_T]],
    num_passes: int,
    get_passes: Callable[[int], IPassGroup],
) -> _T:
    """
    Similar to ``call_with_passes_with_manual_spend`` but automatically spend
    all passes associated with a successful call of ``method``.

    For parameter documentation, see ``call_with_passes_with_manual_spend``.
    """
    return await call_with_passes_with_manual_spend(
        method,
        num_passes,
        get_passes,
        # Commit the spend of the passes when the operation finally succeeds.
        lambda result, pass_group: pass_group.mark_spent(),
    )


class RRefHaver(Protocol):
    """
    Something that has a Foolscap remote reference.
    """

    def _rref(self) -> IRemoteReference:
        """
        Get the Foolscap remote reference.
        """


_S = TypeVar("_S", bound=RRefHaver)


def with_rref(
    f: Callable[Concatenate[_S, IRemoteReference, _P], Awaitable[_T]],
) -> Callable[Concatenate[_S, _P], Deferred[_T]]:
    """
    Decorate a function so that it automatically receives a
    ``IRemoteReference`` as its first argument when called.

    The ``IRemoteReference`` is retrieved by calling ``_rref`` on the first
    argument passed to the function (expected to be ``self``).

    The return type is changed from any ``Awaitable`` to a ``Deferred``
    because this decorator is almost exclusively for methods called by
    Tahoe-LAFS which still requires exactly a ``Deferred`` return value.
    """

    @wraps(f)
    def g(self: _S, /, *args: _P.args, **kwargs: _P.kwargs) -> Deferred[_T]:

        # h adapts an arbitrary Awaitable result to a coroutine.
        async def h() -> _T:
            return await f(self, self._rref(), *args, **kwargs)

        # And then the coroutine is adapted to a Deferred.
        return Deferred.fromCoroutine(h())

    return g


def _encode_passes(group: IPassGroup) -> list[bytes]:
    """
    :param group: A group of passes to encode.

    :return: The encoded form of the passes in the given group.
    """
    return list(t.pass_bytes for t in group.passes)


async def stat_shares(
    rref: IRemoteReference, storage_indexes: list[bytes]
) -> list[dict[int, ShareStat]]:
    unknown = await rref.callRemote(  # type: ignore[no-untyped-call]
        "stat_shares",
        storage_indexes,
    )
    if not isinstance(unknown, list):
        raise ValueError(f"expected stat_share to return list, got {type(unknown)}")

    known: list[dict[int, ShareStat]] = []
    for stats in unknown:
        if not isinstance(stats, dict):
            raise ValueError(
                f"expected stat_share to return list of dict, instead got element of {type(stats)}"
            )

        known_stats: dict[int, ShareStat] = {}
        for (shnum, stat) in stats.items():
            if not isinstance(shnum, int) or not isinstance(stat, ShareStat):
                raise ValueError(
                    f"expected stat_share to return list of dict of int:ShareStat, instead got item of {type(shnum)}:{type(stat)}"
                )

            known_stats[shnum] = stat
        known.append(known_stats)
    return known


async def get_share_sizes(
    rref: IRemoteReference, storage_index: bytes
) -> dict[int, int]:
    unknown_sizes = await rref.callRemote(  # type: ignore[no-untyped-call]
        "share_sizes",
        storage_index,
        None,
    )
    if isinstance(unknown_sizes, dict):
        known_sizes: dict[int, int] = {}
        for shnum, size in unknown_sizes.items():
            if isinstance(shnum, int) and isinstance(size, int):
                known_sizes[shnum] = size
            else:
                raise ValueError(
                    f"expected share_sizes to return dict of ints, instead got item {type(shnum)}:{type(size)}"
                )
        return known_sizes
    raise ValueError(
        f"expected share_sizes to return dict, instead got {type(unknown_sizes)}"
    )


async def slot_testv_and_readv_and_writev(
    rref: IRemoteReference,
    passes: IPassGroup,
    storage_index: bytes,
    secrets: Secrets,
    old_tw_vectors: dict[int, ServerTestWriteVector],
    r_vector: ReadVector,
) -> tuple[bool, dict[int, list[bytes]]]:
    unknown = await rref.callRemote(  # type: ignore[no-untyped-call]
        "slot_testv_and_readv_and_writev",
        _encode_passes(passes),
        storage_index,
        secrets,
        old_tw_vectors,
        r_vector,
    )

    if not isinstance(unknown, tuple):
        raise ValueError(
            f"expected tuple from slot_testv_and_readv_and_writev, instead got {type(unknown)}"
        )

    ok, data_v = unknown
    if not isinstance(ok, bool):
        raise ValueError(
            f"expected bool from slot_testv_and_readv_and_writev, instead got {type(ok)}"
        )

    if not isinstance(data_v, dict):
        raise ValueError(
            f"expected dict from slot_testv_and_readv_and_writev, instead got {type(data_v)}"
        )

    known_data_v: dict[int, list[bytes]] = {}
    for k, v in data_v.items():
        if not isinstance(k, int) or not isinstance(v, list):
            raise ValueError(
                f"expected int:list element from slot_testv_and_readv_and_writev, instead got {type(k)}:{type(v)}"
            )

        read_v: list[bytes] = []
        for unknown_data in v:
            if not isinstance(unknown_data, bytes):
                raise ValueError(
                    f"expected bytes element from slot_testv_and_readv_and_writev, instead got {type(unknown_data)}"
                )
            read_v.append(unknown_data)
        known_data_v[k] = read_v
    return ok, known_data_v


@implementer(IStorageServer)
@define
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
        valid ``IRemoteReference`` corresponding to the server-side object for
        this scheme.

    :ivar _get_passes: A callable to use to retrieve passes which can be used
        to authorize an operation.  The first argument is utf-8 encoded
        message binding the passes to the request for which they will be used.
        The second gives the number of passes to request.
    """

    _expected_remote_interface_name = (
        "RIPrivacyPassAuthorizedStorageServer.tahoe.privatestorage.io"
    )
    _pass_value: int = field(validator=positive_integer)
    _get_rref: Callable[[], IRemoteReference]
    _get_passes: Callable[[bytes, int], IPassGroup]
    _clock: IReactorTime = field(
        validator=provides(IReactorTime),
        default=Factory(partial(namedAny, "twisted.internet.reactor")),
    )

    def _rref(self) -> IRemoteReference:
        rref = self._get_rref()
        # rref provides foolscap.ipb.IRemoteReference but in practice it is a
        # foolscap.referenceable.RemoteReference instance.  The interface
        # doesn't give us enough functionality to verify that the reference is
        # to the right sort of thing but the concrete type does.
        #
        # Foolscap development isn't exactly racing along and if we're lucky
        # we'll switch to HTTP before too long anyway.
        assert isinstance(rref, RemoteReference)
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
    async def get_version(self, rref: IRemoteReference) -> dict[bytes, Any]:
        unknown_version = await rref.callRemote(  # type: ignore[no-untyped-call]
            "get_version",
        )
        if isinstance(unknown_version, dict):
            known_version: dict[bytes, Any] = {}
            for k, v in unknown_version.items():
                if isinstance(k, bytes):
                    known_version[k] = v
                else:
                    raise ValueError(
                        f"expected get_Version to return dict with bytes keys, instead got {type(k)}"
                    )
            return known_version
        raise ValueError(
            f"expected get_version to return dict, instead got {type(unknown_version)}"
        )

    def _spend_for_allocate_buckets(
        self,
        allocated_size: int,
        result: tuple[set[int], dict[int, Any]],
        pass_group: IPassGroup,
    ) -> None:
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
    async def allocate_buckets(
        self,
        rref: IRemoteReference,
        storage_index: bytes,
        renew_secret: bytes,
        cancel_secret: bytes,
        sharenums: set[int],
        allocated_size: int,
        canary: IRemoteReference,
    ) -> tuple[set[int], dict[int, Any]]:
        num_passes = required_passes(
            self._pass_value, [allocated_size] * len(sharenums)
        )

        async def call(passes: IPassGroup) -> tuple[set[int], dict[int, Any]]:
            alreadygot, buckets = await rref.callRemote(  # type: ignore[no-untyped-call]
                "allocate_buckets",
                _encode_passes(passes),
                storage_index,
                renew_secret,
                cancel_secret,
                sharenums,
                allocated_size,
                canary,
            )
            return alreadygot, buckets

        msg = allocate_buckets_message(storage_index)
        return await call_with_passes_with_manual_spend(
            call,
            num_passes,
            lambda passes: self._get_passes(msg, passes),
            lambda result, passes: self._spend_for_allocate_buckets(
                allocated_size, result, passes
            ),
        )

    @with_rref
    async def get_buckets(
        self,
        rref: IRemoteReference,
        storage_index: bytes,
    ) -> dict[int, Any]:
        unknown_buckets = await rref.callRemote(  # type: ignore[no-untyped-call]
            "get_buckets",
            storage_index,
        )
        if isinstance(unknown_buckets, dict):
            known_buckets: dict[int, Any] = {}
            for k, v in unknown_buckets.items():
                if isinstance(k, int):
                    known_buckets[k] = v
                else:
                    raise ValueError(
                        f"expected get_buckets to return dict with int keys, instead got {type(k)}"
                    )
            return known_buckets
        raise ValueError(
            f"expected get_buckets to return dict, instead got {type(unknown_buckets)}"
        )

    @with_rref
    async def add_lease(
        self,
        rref: IRemoteReference,
        storage_index: bytes,
        renew_secret: bytes,
        cancel_secret: bytes,
    ) -> None:
        share_sizes = (await get_share_sizes(rref, storage_index)).values()
        num_passes = required_passes(self._pass_value, share_sizes)

        async def call(passes: IPassGroup) -> None:
            await rref.callRemote(  # type: ignore[no-untyped-call]
                "add_lease",
                _encode_passes(passes),
                storage_index,
                renew_secret,
                cancel_secret,
            )
            return None

        await call_with_passes(
            call,
            num_passes,
            partial(self._get_passes, add_lease_message(storage_index)),
        )
        return None

    @with_rref
    async def stat_shares(
        self, rref: IRemoteReference, storage_indexes: list[bytes]
    ) -> list[dict[int, ShareStat]]:
        return await stat_shares(rref, storage_indexes)

    @with_rref
    @log_call_coroutine("zkapauthorizer:storage-client:advise-corrupt-share")
    async def advise_corrupt_share(
        self,
        rref: IRemoteReference,
        share_type: bytes,
        storage_index: bytes,
        shnum: int,
        reason: bytes,
    ) -> None:
        await rref.callRemote(  # type: ignore[no-untyped-call]
            "advise_corrupt_share",
            share_type,
            storage_index,
            shnum,
            reason,
        )
        return None

    @with_rref
    @log_call_coroutine("zkapauthorizer:storage-client:slot_testv_and_readv_and_writev")
    async def slot_testv_and_readv_and_writev(
        self,
        rref: IRemoteReference,
        storage_index: bytes,
        secrets: Secrets,
        tw_vectors: dict[int, ClientTestWriteVector],
        r_vector: ReadVector,
    ) -> tuple[bool, dict[int, list[bytes]]]:
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
            [stats] = await stat_shares(rref, [storage_index])
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

        async def call(passes: IPassGroup) -> tuple[bool, dict[int, list[bytes]]]:
            return await slot_testv_and_readv_and_writev(
                rref,
                passes,
                storage_index,
                secrets,
                old_tw_vectors,
                r_vector,
            )

        return await call_with_passes(
            call,
            num_passes,
            partial(
                self._get_passes,
                slot_testv_and_readv_and_writev_message(storage_index),
            ),
        )

    @with_rref
    async def slot_readv(
        self,
        rref: IRemoteReference,
        storage_index: bytes,
        shares: list[int],
        r_vector: ReadVector,
    ) -> dict[int, bytes]:
        result = await rref.callRemote(  # type: ignore[no-untyped-call]
            "slot_readv",
            storage_index,
            shares,
            r_vector,
        )
        # XXX If this function raises an exception, the read fails with no
        # additional detail logged anywhere.
        return result  # type: ignore[no-any-return]
