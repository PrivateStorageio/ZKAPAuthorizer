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
``allmydata.storage``-related helpers shared across the test suite.
"""

from functools import partial
from itertools import islice
from os import SEEK_CUR
from struct import pack
from typing import Callable

import attr
from challenge_bypass_ristretto import RandomToken, SigningKey
from twisted.python.filepath import FilePath
from zope.interface import implementer

from ..model import NotEnoughTokens, Pass, UnblindedToken
from ..spending import IPassFactory, PassGroup
from .privacypass import make_passes
from .strategies import bytes_for_share  # Not really a strategy...

# Hard-coded in Tahoe-LAFS
LEASE_INTERVAL = 60 * 60 * 24 * 31


def reset_storage_server(storage_server):
    """
    Restore a storage server to a default state.  This includes
    deleting all of the shares it holds.

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server with some on-disk shares to delete.
    """
    # A storage server is read-write by default.
    storage_server.readonly_storage = False

    starts = [
        FilePath(storage_server.sharedir),
        FilePath(storage_server.corruption_advisory_dir),
    ]
    for start in starts:
        for p in start.walk():
            if p is not start:
                p.remove()


def write_toy_shares(
    storage_server,
    storage_index,
    renew_secret,
    cancel_secret,
    sharenums,
    size,
):
    """
    Write some immutable shares to the given storage server.

    :param allmydata.storage.server.StorageServer storage_server:
    :param bytes storage_index:
    :param bytes renew_secret:
    :param bytes cancel_secret:
    :param set[int] sharenums:
    :param int size:
    """
    _, allocated = storage_server.allocate_buckets(
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        size,
    )
    for (sharenum, writer) in allocated.items():
        writer.write(0, bytes_for_share(sharenum, size))
        writer.close()


def whitebox_write_sparse_share(sharepath, version, size, leases, now):
    """
    Write a zero-filled sparse (if the filesystem supports it) immutable share
    to the given path.

    This assumes knowledge of the Tahoe-LAFS share file format.

    :param FilePath sharepath: The path to which to write the share file.
    :param int version: The share version to write to the file.
    :param int size: The share data size to write.
    :param list leases: Renewal secrets for leases to write to the share file.
    :param float now: The current time as a POSIX timestamp.
    """
    # Maybe-saturated size (what at least one Tahoe-LAFS comment claims is
    # appropriate for large files)
    internal_size = min(size, 2 ** 32 - 1)
    apparent_size = size

    header_format = ">LLL"
    lease_format = ">L32s32sL"
    with sharepath.open("wb") as share:
        share.write(
            pack(
                header_format,
                version,
                internal_size,
                len(leases),
            ),
        )
        # Try to make it sparse by skipping all the data.
        share.seek(apparent_size - 1, SEEK_CUR),
        share.write(b"\0")
        share.write(
            b"".join(
                pack(
                    lease_format,
                    # no owner
                    0,
                    renew,
                    # no cancel secret
                    b"",
                    # expiration timestamp
                    int(now + LEASE_INTERVAL),
                )
                for renew in leases
            ),
        )


def integer_passes(limit: int) -> Callable[[bytes, int], list[int]]:
    """
    :return: A function which can be used to get a number of passes.  The
        function accepts a unicode request-binding message and an integer
        number of passes.  It returns a list of integers which serve as
        passes.  Successive calls to the function return unique pass values.
    """
    counter = iter(range(limit))

    def get_passes(message, num_passes):
        result = list(islice(counter, num_passes))
        if len(result) < num_passes:
            raise NotEnoughTokens()
        return result

    return get_passes


def get_passes(
    message: bytes, count: int, signing_key: SigningKey
) -> list[RandomToken]:
    """
    :param bytes message: Request-binding message for PrivacyPass.

    :param int count: The number of passes to get.

    :param SigningKey signing_key: The key to use to sign the passes.

    :return list[Pass]: ``count`` new random passes signed with the given key
        and bound to the given message.
    """
    assert isinstance(message, bytes)
    return make_passes(
        signing_key,
        message,
        [RandomToken.create() for n in range(count)],
    )


def privacypass_passes(signing_key):
    """
    Get a PrivacyPass issuing function.

    :param SigningKey signing_key: The key to use to issue passes.

    :return: Return a function which can be used to get a number of passes.
        The function accepts a unicode request-binding message and an integer
        number of passes.  It returns a list of real pass values signed by the
        given key.  Successive calls to the function return unique passes.
    """
    return partial(get_passes, signing_key=signing_key)


def pass_factory(get_passes):
    """
    Get a new factory for passes.

    :param (unicode -> int -> [pass]) get_passes: A function the factory can
        use to get new passes.
    """
    return _PassFactory(get_passes=get_passes)


@implementer(IPassFactory)
@attr.s
class _PassFactory(object):
    """
    A stateful pass issuer.

    :ivar _get_passes: A function for getting passes.

    :ivar in_use: All of the passes given out without a confirmed
        terminal state.

    :ivar invalid: All of the passes given out and returned using
        ``IPassGroup.invalid`` mapped to the reason given.

    :ivar spent: All of the passes given out and returned via
        ``IPassGroup.mark_spent``.

    :ivar issued: All of the passes ever given out.

    :ivar returned: A list of passes which were given out but then returned
        via ``IPassGroup.reset``.
    """

    _get_passes: Callable[[bytes, int], list[bytes]] = attr.ib()

    returned: list[bytes] = attr.ib(default=attr.Factory(list), init=False)
    in_use: set[bytes] = attr.ib(default=attr.Factory(set), init=False)
    invalid: dict[bytes, str] = attr.ib(default=attr.Factory(dict), init=False)
    spent: set[bytes] = attr.ib(default=attr.Factory(set), init=False)
    issued: set[bytes] = attr.ib(default=attr.Factory(set), init=False)

    def get(self, message: bytes, num_passes: int) -> PassGroup:
        passes: list[bytes] = []
        if self.returned:
            passes.extend(self.returned[:num_passes])
            del self.returned[:num_passes]
            num_passes -= len(passes)
        passes.extend(self._get_passes(message, num_passes))
        self.issued.update(passes)
        self.in_use.update(passes)
        return PassGroup(
            message, self, [(UnblindedToken(t), Pass(t, t)) for t in passes]
        )

    def _clear(self):
        """
        Forget about all passes: returned, in use, spent, invalid, issued.
        """
        del self.returned[:]
        self.in_use.clear()
        self.invalid.clear()
        self.spent.clear()
        self.issued.clear()

    def _mark_spent(self, passes):
        for p in passes:
            if p not in self.in_use:
                raise ValueError("Pass {} cannot be spent, it is not in use.".format(p))
        self.spent.update(passes)
        self.in_use.difference_update(passes)

    def _mark_invalid(self, reason, passes):
        for p in passes:
            if p not in self.in_use:
                raise ValueError(
                    "Pass {} cannot be invalid, it is not in use.".format(p)
                )
        self.invalid.update(dict.fromkeys(passes, reason))
        self.in_use.difference_update(passes)

    def _reset(self, passes):
        for p in passes:
            if p not in self.in_use:
                raise ValueError("Pass {} cannot be reset, it is not in use.".format(p))
        self.returned.extend(passes)
        self.in_use.difference_update(passes)
