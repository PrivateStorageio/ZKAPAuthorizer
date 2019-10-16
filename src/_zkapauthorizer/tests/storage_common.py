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

from twisted.python.filepath import (
    FilePath,
)

from .strategies import (
    # Not really a strategy...
    bytes_for_share,
)

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
