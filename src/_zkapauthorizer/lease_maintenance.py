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
This module implements a service which periodically spends ZKAPs to
refresh leases on all shares reachable from a root.
"""

from functools import (
    partial,
)
from datetime import (
    datetime,
    timedelta,
)

import attr

from twisted.internet.defer import (
    inlineCallbacks,
    maybeDeferred,
)
from twisted.application.service import (
    Service,
)
from twisted.python.log import (
    err,
)

from allmydata.interfaces import (
    IDirectoryNode,
)
from allmydata.util.hashutil import (
    file_renewal_secret_hash,
    bucket_renewal_secret_hash,
)

SERVICE_NAME = u"lease maintenance service"

@inlineCallbacks
def visit_storage_indexes(root_node, visit):
    """
    Call a visitor with the storage index of ``root_node`` and that of all
    nodes reachable from it.

    :param IFilesystemNode root_node: The node from which to start.

    :param visit: A one-argument callable.  It will be called with the storage
        index of all visited nodes.

    :return Deferred: A Deferred which fires after all nodes have been
        visited.
    """
    stack = [root_node]
    while stack:
        elem = stack.pop()
        visit(elem.get_storage_index())
        if IDirectoryNode.providedBy(elem):
            children = yield elem.list()
            # Produce consistent results by forcing some consistent ordering
            # here.  This will sort by name.
            stable_children = sorted(children.items())
            for (name, (child_node, child_metadata)) in stable_children:
                stack.append(child_node)


def iter_storage_indexes(visit_assets):
    """
    Get an iterator over storage indexes of all nodes visited by
    ``visit_assets``.

    :param visit_assets: A one-argument function which takes a visit function
        and calls it with all nodes to visit.

    :return Deferred[list[bytes]]: A Deferred that fires with a list of
        storage indexes from the visited nodes.  The list is in an arbitrary
        order and does not include duplicates if any nodes were visited more
        than once.
    """
    storage_indexes = set()
    visit = storage_indexes.add
    d = visit_assets(visit)
    # Create some order now that we've ensured they're unique.
    d.addCallback(lambda ignored: list(storage_indexes))
    return d


@inlineCallbacks
def renew_leases(visit_assets, storage_broker, secret_holder, min_lease_remaining, now):
    """
    Check the leases on a group of nodes for those which are expired or close
    to expiring and renew such leases.

    :param visit_assets: A one-argument callable which takes a visitor
        function and calls it with the storage index of every node to check.

    :param StorageFarmBroker storage_broker: A storage broker which can supply
        the storage servers where the nodes should be checked.

    :param SecretHolder secret_holder: The source of the renew secret for any
        leases which require renewal.

    :param timedelta min_lease_remaining: The minimum amount of time remaining
        to allow on a lease without renewing it.

    :param now: A no-argument function returning the current time, as a
        datetime instance, for comparison against lease expiration time.

    :return Deferred: A Deferred which fires when all visitable nodes have
        been checked and any leases renewed which required it.
    """
    storage_indexes = yield iter_storage_indexes(visit_assets)

    renewal_secret = secret_holder.get_renewal_secret()
    servers = storage_broker.get_connected_servers()

    for server in servers:
        # Consider parallelizing this.
        yield renew_leases_on_server(
            min_lease_remaining,
            renewal_secret,
            storage_indexes,
            server,
            now(),
        )


@inlineCallbacks
def renew_leases_on_server(
        min_lease_remaining,
        renewal_secret,
        storage_indexes,
        server,
        now,
):
    """
    Check leases on the shares for the given storage indexes on the given
    storage server for those which are expired or close to expiring and renew
    such leases.

    :param timedelta min_lease_remaining: The minimum amount of time remaining
        to allow on a lease without renewing it.

    :param renewal_secret: A seed for the renewal secret hash calculation for
        any leases which need to be renewed.

    :param list[bytes] storage_indexes: The storage indexes to check.

    :param StorageServer server: The storage server on which to check.

    :param datetime now: The current time for comparison against the least
        expiration time.

    :return Deferred: A Deferred which fires after all storage indexes have
        been checked and any leases that need renewal have been renewed.
    """
    stats = yield server.stat_shares(storage_indexes)
    for storage_index, stat_dict in zip(storage_indexes, stats):
        if not stat_dict:
            # The server has no shares for this storage index.
            continue
        # All shares have the same lease information.
        stat = stat_dict.popitem()[1]
        if needs_lease_renew(min_lease_remaining, stat, now):
            yield renew_lease(renewal_secret, storage_index, server)


def renew_lease(renewal_secret, storage_index, server):
    """
    Renew the lease on the shares in one storage index on one server.

    :param renewal_secret: A seed for the renewal secret hash calculation for
        any leases which need to be renewed.

    :param bytes storage_index: The storage index to operate on.

    :param StorageServer server: The storage server to operate on.

    :return Deferred: A Deferred that fires when the lease has been renewed.
    """
    # See allmydata/immutable/checker.py, _get_renewal_secret
    renew_secret = bucket_renewal_secret_hash(
        file_renewal_secret_hash(
            renewal_secret,
            storage_index,
        ),
        server.get_lease_seed(),
    )
    return server.renew_lease(
        storage_index,
        renew_secret,
    )


def needs_lease_renew(min_lease_remaining, stat, now):
    """
    Determine if a lease needs renewal.

    :param timedelta min_lease_remaining: The minimum amount of time remaining
        to allow on a lease without renewing it.

    :param ShareStat stat: The metadata about a share to consider.

    :param datetime now: The current time for comparison against the lease
        expiration time.

    :return bool: ``True`` if the lease needs to be renewed, ``False``
        otherwise.
    """
    remaining = datetime.utcfromtimestamp(stat.lease_expiration) - now
    return remaining < min_lease_remaining


@attr.s
class _FuzzyTimerService(Service):
    """
    A service to periodically, but not *too* periodically, run an operation.

    :ivar operation: A no-argument callable to fuzzy-periodically run.  It may
        return a Deferred in which case the next run will not be scheduled
        until the Deferred fires.

    :ivar timedelta initial_interval: The amount of time to wait before the first
        run of the operation.

    :ivar sample_interval_distribution: A no-argument callable which returns a
       number of seconds as a float giving the amount of time to wait before
       the next run of the operation.  It will be called each time the
       operation completes.

    :ivar IReactorTime reactor: A Twisted reactor to use to schedule runs of
        the operation.
    """
    name = attr.ib()
    operation = attr.ib()
    initial_interval = attr.ib()
    sample_interval_distribution = attr.ib()
    reactor = attr.ib()

    def startService(self):
        Service.startService(self)
        self.reactor.callLater(
            self.initial_interval.total_seconds(),
            self._iterate,
        )

    def _iterate(self):
        """
        Run the operation once and then schedule it to run again.
        """
        d = maybeDeferred(self.operation)
        d.addErrback(err, "Fuzzy timer service ({})")
        d.addCallback(lambda ignored: self._schedule())

    def _schedule(self):
        """
        Schedule the next run of the operation.
        """
        self._call = self.reactor.callLater(
            self.sample_interval_distribution().total_seconds(),
            self._iterate,
        )


def lease_maintenance_service(
        maintain_leases,
        reactor,
        last_run,
        random,
        interval_mean=None,
        interval_range=None,
):
    """
    Get an ``IService`` which will maintain leases on ``root_node`` and any
    nodes directly or transitively reachable from it.

    :param IReactorClock reactor: A Twisted reactor for scheduling renewal
        activity.

    :param datetime last_run: The time at which lease maintenance last ran to
        inform an adjustment to the first interval before running it again, or
        ``None`` not to make such an adjustment.

    :param random: An object like ``random.Random`` which can be used as a
        source of scheduling delay.

    :param timedelta interval_mean: The mean time between lease renewal checks.

    :param timedelta interval_range: The range of the uniform distribution of
        lease renewal checks (centered on ``interval_mean``).

    :param maintain_leases: A no-argument callable which performs a round of
        lease-maintenance.  The resulting service calls this periodically.
    """
    if interval_mean is None:
        interval_mean = timedelta(days=26)
    if interval_range is None:
        interval_range = timedelta(days=4)
    halfrange = interval_range / 2

    def sample_interval_distribution():
        return timedelta(
            seconds=random.uniform(
                (interval_mean - halfrange).total_seconds(),
                (interval_mean + halfrange).total_seconds(),
            ),
        )
    if last_run is None:
        initial_interval = sample_interval_distribution()
    else:
        initial_interval = calculate_initial_interval(
            sample_interval_distribution,
            last_run,
            datetime.utcfromtimestamp(reactor.seconds()),
        )
        initial_interval = max(
            initial_interval,
            timedelta(0),
        )

    return _FuzzyTimerService(
        SERVICE_NAME,
        maintain_leases,
        initial_interval,
        sample_interval_distribution,
        reactor,
    )


def visit_storage_indexes_from_root(visitor, root_node):
    """
    An operation for ``lease_maintenance_service`` which applies the given
    visitor to ``root_node`` and all its children.

    :param visitor: A one-argument callable which takes the traversal function
        and which should call it as desired.

    :param IFilesystemNode root_node: The filesystem node at which traversal
        will begin.

    :return: A no-argument callable to perform the visits.
    """
    return partial(
        visitor,
        partial(visit_storage_indexes, root_node),
    )


def maintain_leases_from_root(root_node, storage_broker, secret_holder, min_lease_remaining, get_now):
    """
    An operation for ``lease_maintenance_service`` which visits ``root_node``
    and all its children and renews their leases if they have
    ``min_lease_remaining`` or less on them.

    :param IFilesystemNode root_node: A Tahoe-LAFS filesystem node to use as
        the root of a node hierarchy to be maintained.

    :param StorageFarmBroker storage_broker: The storage broker which can put
        us in touch with storage servers where shares of the nodes to maintain
        might be found.

    :param SecretHolder secret_holder: The Tahoe-LAFS client node secret
        holder which can give us the lease renewal secrets needed to renew
        leases.

    :param timedelta min_lease_remaining: The minimum amount of time remaining
        to allow on a lease without renewing it.

    :param get_now: A no-argument callable that returns the current time as a
        ``datetime`` instance.

    :return: A no-argument callable to perform the maintenance.
    """
    def visitor(visit_assets):
        return renew_leases(
            visit_assets,
            storage_broker,
            secret_holder,
            min_lease_remaining,
            get_now,
        )

    return visit_storage_indexes_from_root(
        visitor,
        root_node,
    )


def calculate_initial_interval(sample_interval_distribution, last_run, now):
    """
    Determine how long to wait before performing an initial (for this process)
    scan for aging leases.

    :param sample_interval_distribution: See ``_FuzzyTimerService``.
    :param datetime last_run: The time of the last scan.
    :param datetime now: The current time.
    """
    since_last_run = now - last_run
    initial_interval = sample_interval_distribution() - since_last_run
    return initial_interval
