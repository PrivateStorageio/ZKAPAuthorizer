from collections.abc import Awaitable

from attrs import define, field
from twisted.application.service import Service
from twisted.internet.defer import CancelledError, Deferred
from twisted.python.lockfile import FilesystemLock

from .config import REPLICA_RWCAP_BASENAME, _Config
from .model import VoucherStore
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


def replication_service(reactor, node, store):
    """
    Return a service which implements the replication process documented in
    the ``backup-recovery`` design document:
    """
    return _ReplicationService(reactor, node.config, store)


SERVICE_NAME = "replication-service"


@define
class _ReplicationService(Service):
    """
    Perform all activity related to maintaining a remote replica of the local
    ZKAPAuthorizer database.

    :ivar _reactor: The reactor to use for this activity.

    :ivar _config: The Tahoe-LAFS configuration for the node this service runs
        in.

    :ivar _store: The database for the plugin instance for which this service
        performs replication.
    """

    name = SERVICE_NAME

    _reactor = field()
    _config: _Config = field()
    _store: VoucherStore = field()

    def startService(self):
        # Observe changes Tell the store to initiate replication when appropriate.
        self._replicating = self._store.observe_events(
            lambda conn, replica_dircap: None,
        )

    def stopService(self):
        replicating = self._replicating
        self._replicating = None

        def catch_cancelled(err):
            err.trap(CancelledError)
            return None

        replicating.addErrback(catch_cancelled)
        replicating.cancel()
