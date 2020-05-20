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

from functools import (
    partial,
)

from os import (
    SEEK_CUR,
)
from struct import (
    pack,
)

from itertools import (
    count,
    islice,
)

import attr

from twisted.python.filepath import (
    FilePath,
)

from challenge_bypass_ristretto import (
    RandomToken,
)

from .strategies import (
    # Not really a strategy...
    bytes_for_share,
)

from .privacypass import (
    make_passes,
)

from ..model import (
    Pass,
)

# Hard-coded in Tahoe-LAFS
LEASE_INTERVAL = 60 * 60 * 24 * 31

def cleanup_storage_server(storage_server):
    """
    Delete all of the shares held by the given storage server.

    :param allmydata.storage.server.StorageServer storage_server: The storage
        server with some on-disk shares to delete.
    """
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
        canary,
):
    """
    Write some immutable shares to the given storage server.

    :param allmydata.storage.server.StorageServer storage_server:
    :param bytes storage_index:
    :param bytes renew_secret:
    :param bytes cancel_secret:
    :param set[int] sharenums:
    :param int size:
    :param IRemoteReference canary:
    """
    _, allocated = storage_server.remote_allocate_buckets(
        storage_index,
        renew_secret,
        cancel_secret,
        sharenums,
        size,
        canary=canary,
    )
    for (sharenum, writer) in allocated.items():
        writer.remote_write(0, bytes_for_share(sharenum, size))
        writer.remote_close()


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
                for renew
                in leases
            ),
        )


def integer_passes():
    """
    :return: Return a function which can be used to get a number of passes.
        The function accepts a unicode request-binding message and an integer
        number of passes.  It returns a list of integers which serve as passes.
        Successive calls to the function return unique pass values.
    """
    counter = count(0)
    def get_passes(message, num_passes):
        return list(islice(counter, num_passes))
    return get_passes


def get_passes(message, count, signing_key):
    """
    :param unicode message: Request-binding message for PrivacyPass.

    :param int count: The number of passes to get.

    :param SigningKEy signing_key: The key to use to sign the passes.

    :return list[Pass]: ``count`` new random passes signed with the given key
        and bound to the given message.
    """
    return list(
        Pass(*pass_.split(u" "))
        for pass_
        in make_passes(
            signing_key,
            message,
            list(RandomToken.create() for n in range(count)),
        )
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


def pass_factory(get_passes=None):
    """
    Get a new factory for passes.

    :param (unicode -> int -> [pass]) get_passes: A function the factory can
        use to get new passes.
    """
    if get_passes is None:
        get_passes = integer_passes()
    return _PassFactory(get_passes=get_passes)


@attr.s
class _PassFactory(object):
    """
    A stateful pass issuer.

    :ivar (unicode -> int -> [bytes]) _get_passes: A function for getting
        passes.

    :ivar set[int] issued: All of the passes ever given out.

    """
    _get_passes = attr.ib()
    issued = attr.ib(default=attr.Factory(set), init=False)

    def get(self, message, num_passes):
        passes = []
        passes.extend(self._get_passes(message, num_passes))
        self.issued.update(passes)
        return passes
