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
A system for replicating local SQLite3 database state to remote storage.
"""

__all__ = [
    "ReplicationAlreadySetup",
    "fail_setup_replication",
    "setup_tahoe_lafs_replication",
]

from collections.abc import Awaitable
from typing import BinaryIO

from twisted.python.lockfile import FilesystemLock

from .config import REPLICA_RWCAP_BASENAME
from .tahoe import Tahoe, attenuate_writecap


class ReplicationAlreadySetup(Exception):
    """
    An attempt was made to setup of replication but it is already set up.
    """


async def fail_setup_replication():
    """
    A replication setup function that always fails.
    """
    raise Exception("Test not set up for replication")


async def setup_tahoe_lafs_replication(client: Tahoe) -> Awaitable[str]:
    """
    Configure the ZKAPAuthorizer plugin that lives in the Tahoe-LAFS node with
    the given configuration to replicate its state onto Tahoe-LAFS storage
    servers using that Tahoe-LAFS node.
    """
    # Find the configuration path for this node's replica.
    config_path = client.get_private_path(REPLICA_RWCAP_BASENAME)

    # Take an advisory lock on the configuration path to avoid concurrency
    # shennanigans.
    config_lock = FilesystemLock(config_path.path + ".lock")
    config_lock.lock()
    try:

        # Check to see if there is already configuration.
        if config_path.exists():
            raise ReplicationAlreadySetup()

        # Create a directory with it
        rw_cap = await client.make_directory()

        # Store the resulting write-cap in the node's private directory
        config_path.setContent(rw_cap.encode("ascii"))

    finally:
        # On success and failure, release the lock since we're done with the
        # file for now.
        config_lock.unlock()

    # Attenuate it to a read-cap
    rocap = attenuate_writecap(rw_cap)

    # Return the read-cap
    return rocap


async def tahoe_lafs_uploader(
    client: Tahoe,
    recovery_cap: str,
    snapshot_data: BinaryIO,
    entry_name: str,
) -> Awaitable[None]:
    """
    Upload a replica to Tahoe, linking the result into the given
    recovery mutable capbility under the name 'snapshot.sql'
    """
    snapshot_immutable_cap = await client.upload(snapshot_data)
    await client.link(recovery_cap, entry_name, snapshot_immutable_cap)


def get_tahoe_lafs_direntry_uploader(
    client: Tahoe,
    directory_mutable_cap: str,
    entry_name: str = "snapshot.sql",
):
    """
    Bind a Tahoe client to a mutable directory in a callable that will
    upload a BytesIO and link it into the mutable directory under the
    given name.

    :return: A callable that uploads a BytesIO as the latest replica
        snapshot
    """

    async def upload(data: BinaryIO) -> Awaitable[None]:
        await tahoe_lafs_uploader(client, directory_mutable_cap, data, entry_name)

    return upload
