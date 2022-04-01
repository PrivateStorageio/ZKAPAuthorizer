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
from io import BytesIO
from sqlite3 import Connection
from typing import BinaryIO, Callable

import cbor2
from attrs import frozen
from twisted.python.lockfile import FilesystemLock

from .config import REPLICA_RWCAP_BASENAME
from .tahoe import Tahoe, attenuate_writecap


@frozen
class Change:
    """
    Represent an item in a replication event stream
    """

    sequence: int  # the sequence-number of this event
    statement: str  # the SQL statement string


@frozen
class EventStream:
    """
    A series of database operations represented as `Change` instances.
    """

    changes: tuple[Change]

    def highest_sequence(self):
        """
        :return int: the highest sequence number in this EventStream (or
            None if there are no events)
        """
        if not self.changes:
            return None
        return max(change.sequence for change in self.changes)

    # XXX or should we pass in a writable stream to use instead?
    def to_bytes(self) -> BinaryIO:
        """
        :returns BinaryIO: a producer of bytes representing this EventStream.
        """
        return BytesIO(
            cbor2.dumps(
                {
                    "events": tuple(
                        (event.sequence, event.statement.encode("utf8"))
                        for event in self.changes
                    )
                }
            )
        )

    # XXX versioning? or do we handle that higher up?
    @classmethod
    def from_bytes(cls, stream: BinaryIO):
        """
        :returns EventStream: an instance of EventStream from the given
            bytes (which should have been produced by a prior call to
            ``to_bytes``)
        """
        data = cbor2.load(stream)
        return cls(
            changes=tuple(
                Change(seq, statement.decode("utf8"))
                for seq, statement in data["events"]
            )
        )


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
    get_snapshot_data: Callable[[], BinaryIO],
    entry_name: str,
) -> None:
    """
    Upload a replica to Tahoe, linking the result into the given
    recovery mutable capbility under the name 'snapshot.sql'
    """
    snapshot_immutable_cap = await client.upload(get_snapshot_data)
    await client.link(recovery_cap, entry_name, snapshot_immutable_cap)


def get_tahoe_lafs_direntry_uploader(
    client: Tahoe,
    directory_mutable_cap: str,
    entry_name: str = "snapshot.sql",
):
    """
    Bind a Tahoe client to a mutable directory in a callable that will
    upload some data and link it into the mutable directory under the
    given name.

    :return Callable[[Callable[[], BinaryIO]], None]: A callable that
        will upload some data as the latest replica snapshot. The data
        isn't given directly, but instead from a zero-argument callable
        itself to facilitate retrying.
    """

    async def upload(get_data_provider: Callable[[], BinaryIO]) -> None:
        await tahoe_lafs_uploader(
            client, directory_mutable_cap, get_data_provider, entry_name
        )

    return upload


def event_stream_observer(
    replica_dircap: str,
    client: Tahoe,
    conn: Connection,
    max_sequence_difference: int = 5,
) -> Callable[[EventStream], None]:
    """
    Create a function that will be called with a new EventStream every
    time it changes. This will choose whether to upload the
    EventStream or not and whether to prune things from the local
    database.

    :param max_sequence_difference: the maximum number of statements
        before we upload a new EventStream to the replica

    :returns: a Callable that should be called with a new event-stream
    """
    # the last sequence-number we've uploaded
    last_uploaded = [None]

    async def upload(events: EventStream):
        entry_name = f"event-stream-{events.highest_sequence()}"
        await tahoe_lafs_uploader(
            client,
            replica_dircap,
            events.to_bytes,
            entry_name,
        )

    def prune_events(sequence_number):
        with conn as cursor:
            cursor.execute(
                """
                DELETE FROM [event-stream]
                WHERE [sequence-number] <= (?)
                """,
                (sequence_number,),
            )

    async def observer(events: EventStream):
        if (
            last_uploaded[0] is None
            or events.highest_sequence() - last_uploaded[0] > max_sequence_difference
        ):
            await upload(events)
        last_uploaded[0] = events.highest_sequence()
        prune_events(last_uploaded[0])

    return observer
