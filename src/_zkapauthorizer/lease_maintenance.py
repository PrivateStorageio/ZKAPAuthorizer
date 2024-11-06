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

from __future__ import annotations

from datetime import datetime, timedelta
from errno import ENOENT
from random import Random
from typing import (
    Awaitable,
    Callable,
    Coroutine,
    Generic,
    Iterable,
    NewType,
    Optional,
    TypeVar,
)

import attr
from allmydata.client import SecretHolder
from allmydata.interfaces import IDirectoryNode, IFilesystemNode
from allmydata.storage.server import StorageServer
from allmydata.storage_client import StorageFarmBroker
from allmydata.util.hashutil import (
    bucket_cancel_secret_hash,
    bucket_renewal_secret_hash,
    file_cancel_secret_hash,
    file_renewal_secret_hash,
)
from aniso8601 import parse_datetime
from attrs import Factory, define
from twisted.application.service import IService, Service
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IDelayedCall, IReactorTime
from twisted.python.failure import Failure
from twisted.python.filepath import FilePath
from twisted.python.log import err
from typing_extensions import TypeAlias
from zope.interface import implementer

from .config import Config, read_duration
from .foolscap import ShareStat
from .model import ILeaseMaintenanceObserver

SERVICE_NAME = "lease maintenance service"

StorageIndex = NewType("StorageIndex", bytes)
Visitor: TypeAlias = Callable[[StorageIndex], None]
VisitAssets: TypeAlias = Callable[[Visitor], Awaitable[None]]


async def visit_storage_indexes(
    root_nodes: list[IFilesystemNode], visit: Visitor
) -> None:
    """
    Call a visitor with the storage index of each of ``root_nodes`` and
    that of all nodes reachable from them.

    :param root_nodes: The nodes from which to start.

    :param visit: A function to call with the storage index of every visited
        node.

    :return: A coroutine that completes after all nodes have been visited.
    """
    if not isinstance(root_nodes, list):
        raise TypeError(
            "root_nodes must be a list, not {!r}".format(
                root_nodes,
            )
        )
    for node in root_nodes:
        if not IFilesystemNode.providedBy(node):
            raise TypeError(
                "Root nodes must provide IFilesystemNode, {!r} does not".format(
                    node,
                )
            )

    stack = root_nodes[:]
    while stack:
        elem = stack.pop()
        visit(elem.get_storage_index())
        if IDirectoryNode.providedBy(elem):
            children = await elem.list()
            # Produce consistent results by forcing some consistent ordering
            # here.  This will sort by name.
            stable_children = sorted(children.items())
            for name, (child_node, child_metadata) in stable_children:
                stack.append(child_node)


async def iter_storage_indexes(visit_assets: VisitAssets) -> list[StorageIndex]:
    """
    Get an iterator over storage indexes of all nodes visited by
    ``visit_assets``.

    :param visit_assets: A one-argument function which takes a visit function
        and calls it with all nodes to visit.

    :return: A coroutine that completes with a list of storage indexes from
        the visited nodes.  The list is in an arbitrary order and does not
        include duplicates if any nodes were visited more than once.
    """
    storage_indexes: set[StorageIndex] = set()
    visit = storage_indexes.add
    await visit_assets(visit)
    # Create some order now that we've ensured they're unique.
    return list(storage_indexes)


async def renew_leases(
    visit_assets: VisitAssets,
    storage_broker: StorageFarmBroker,
    secret_holder: SecretHolder,
    min_lease_remaining: timedelta,
    get_activity_observer: Callable[[], ILeaseMaintenanceObserver],
    now: Callable[[], datetime],
) -> None:
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

    :param get_activity_observer: A no-argument callable which returns an
        ``ILeaseMaintenanceObserver``.

    :param now: A no-argument function returning the current time, as a
        datetime instance, for comparison against lease expiration time.

    :return Deferred: A Deferred which fires when all visitable nodes have
        been checked and any leases renewed which required it.
    """
    activity = get_activity_observer()

    storage_indexes = await iter_storage_indexes(visit_assets)

    renewal_secret = secret_holder.get_renewal_secret()
    cancel_secret = secret_holder.get_cancel_secret()
    servers = list(
        server.get_storage_server() for server in storage_broker.get_connected_servers()
    )

    for server in servers:
        # Consider parallelizing this.
        await renew_leases_on_server(
            min_lease_remaining,
            renewal_secret,
            cancel_secret,
            storage_indexes,
            server,
            activity,
            now(),
        )

    activity.finish()


async def renew_leases_on_server(
    min_lease_remaining: timedelta,
    renewal_secret: bytes,
    cancel_secret: bytes,
    storage_indexes: list[StorageIndex],
    server: StorageServer,
    activity: ILeaseMaintenanceObserver,
    now: datetime,
) -> None:
    """
    Check leases on the shares for the given storage indexes on the given
    storage server for those which are expired or close to expiring and renew
    such leases.

    :param min_lease_remaining: The minimum amount of time remaining to allow
        on a lease without renewing it.

    :param renewal_secret: See ``renew_lease``.

    :param cancel_secret: See ``renew_lease``.

    :param storage_indexes: The storage indexes to check.

    :param server: The storage server on which to check.

    :param activity: An object which will receive events allowing it to
        observe the lease maintenance activity.

    :param now: The current time for comparison against the least expiration
        time.

    :return: A coroutine which completes after all storage indexes have been
        checked and any leases that need renewal have been renewed.
    """
    stats = await server.stat_shares(storage_indexes)
    for storage_index, stat_dict in zip(storage_indexes, stats):
        if not stat_dict:
            # The server has no shares for this storage index.
            continue

        # Keep track of what's been seen.
        activity.observe([stat.size for stat in stat_dict.values()])

        # Each share has its own leases and each lease has its own expiration
        # time.  For each share the server only returns the lease with the
        # expiration time farthest in the future.
        #
        # There is no API for renewing leases on just *some* shares!  It is
        # all or nothing.  So from the server's response we find the share
        # that will have no active lease soonest and make our decision about
        # whether to renew leases at this storage index or not based on that.
        most_endangered = soonest_expiration(stat_dict.values())
        if needs_lease_renew(min_lease_remaining, most_endangered, now):
            await renew_lease(renewal_secret, cancel_secret, storage_index, server)


def soonest_expiration(stats: Iterable[ShareStat]) -> ShareStat:
    """
    :return: The share stat from ``stats`` with a lease which expires before
        all others.
    """
    return min(
        stats,
        key=lambda stat: stat.lease_expiration,
    )


async def renew_lease(
    renewal_secret: bytes,
    cancel_secret: bytes,
    storage_index: StorageIndex,
    server: StorageServer,
) -> None:
    """
    Renew the lease on the shares in one storage index on one server.

    :param renewal_secret: A seed for the renewal secret hash calculation for
        any leases which need to be renewed.

    :param cancel_secret: A seed for the cancel secret hash calculation for
        any leases which need to be renewed.

    :param storage_index: The storage index to operate on.

    :param server: The storage server to operate on.

    :return: A coroutine which completes when the lease has been renewed.
    """
    # See allmydata/immutable/checker.py, _get_renewal_secret
    renew_secret = bucket_renewal_secret_hash(
        file_renewal_secret_hash(
            renewal_secret,
            storage_index,
        ),
        server.get_lease_seed(),
    )
    cancel_secret = bucket_cancel_secret_hash(
        file_cancel_secret_hash(
            cancel_secret,
            storage_index,
        ),
        server.get_lease_seed(),
    )
    # Use add_lease to add a new lease *or* renew an existing one with a
    # matching renew secret.
    await server.add_lease(
        storage_index,
        renew_secret,
        cancel_secret,
    )


def needs_lease_renew(
    min_lease_remaining: timedelta, stat: ShareStat, now: datetime
) -> bool:
    """
    Determine if a lease needs renewal.

    :param min_lease_remaining: The minimum amount of time remaining to allow
        on a lease without renewing it.

    :param stat: The metadata about a share to consider.

    :param now: The current time for comparison against the lease expiration
        time.

    :return: ``True`` if the lease needs to be renewed, ``False`` otherwise.
    """
    remaining = datetime.utcfromtimestamp(stat.lease_expiration) - now
    return remaining < min_lease_remaining


_C = TypeVar("_C")


@define
class _FuzzyTimerService(Service, Generic[_C]):
    """
    A service to periodically, but not *too* periodically, run an operation.

    :ivar operation: A no-argument callable to fuzzy-periodically run.  It may
        return a Deferred in which case the next run will not be scheduled
        until the Deferred fires.

    :ivar timedelta initial_interval: The amount of time to wait before the first
        run of the operation.

    :ivar sample_interval_distribution: A no-argument callable which returns
       an amount of time to wait before the next run of the operation.  It
       will be called each time the operation completes.

    :ivar IReactorTime reactor: A Twisted reactor to use to schedule runs of
        the operation.

    :ivar get_config: A function to call to return the service's
        configuration.  The configuration is represented as a service-specific
        object.
    """

    name: str
    operation: Callable[[], Awaitable[None]]
    initial_interval: timedelta
    sample_interval_distribution: Callable[[], timedelta]
    get_config: Callable[[], _C]
    reactor: IReactorTime

    _call: Optional[IDelayedCall] = None

    def startService(self) -> None:
        Service.startService(self)  # type: ignore[no-untyped-call]
        self._call = self.reactor.callLater(
            self.initial_interval.total_seconds(),
            self._iterate,
        )

    def stopService(self) -> None:
        if self._call is not None:
            self._call.cancel()
            self._call = None
        return Service.stopService(self)  # type: ignore[no-untyped-call,no-any-return]

    def _iterate(self) -> None:
        """
        Run the operation once and then schedule it to run again.
        """

        async def go() -> None:
            try:
                await self.operation()
            except:
                f = Failure()  # type: ignore[no-untyped-call]
                err(f, f"Fuzzy timer service ({self.name})")  # type: ignore[no-untyped-call]
            self._schedule()

        Deferred.fromCoroutine(go())

    def _schedule(self) -> None:
        """
        Schedule the next run of the operation.
        """
        self._call = self.reactor.callLater(
            self.sample_interval_distribution().total_seconds(),
            self._iterate,
        )


def lease_maintenance_service(
    maintain_leases: Callable[[], Awaitable[None]],
    reactor: IReactorTime,
    last_run_path: FilePath,
    random: Random,
    lease_maint_config: LeaseMaintenanceConfig,
) -> IService:
    """
    Get an ``IService`` which will maintain leases on ``root_node`` and any
    nodes directly or transitively reachable from it.

    :param reactor: A Twisted reactor for scheduling renewal activity.

    :param last_run_path: A path containing the time (as an ISO8601 datetime
        string) at which lease maintenance last ran to inform an adjustment to
        the first interval before running it again.  If no file exists at the
        path it is treated as though there has been no previous run.  The path
        will also be rewritten on each run to update this value.

    :param random: An object like ``random.Random`` which can be used as a
        source of scheduling delay.

    :param lease_maint_config: Configuration for the tweakable lease
        maintenance parameters.

    :param maintain_leases: A no-argument callable which performs a round of
        lease-maintenance.  The resulting service calls this periodically.
    """
    interval_mean = lease_maint_config.crawl_interval_mean
    interval_range = lease_maint_config.crawl_interval_range
    halfrange = interval_range // 2

    def sample_interval_distribution() -> timedelta:
        return timedelta(
            seconds=random.uniform(
                (interval_mean - halfrange).total_seconds(),
                (interval_mean + halfrange).total_seconds(),
            ),
        )

    # Rather than an all-or-nothing last-run time we probably eventually want
    # to have a more comprehensive record of the state when we were last
    # interrupted.  This would remove the unfortunate behavior of restarting
    # from the beginning if we shut down during a lease scan.  Shutting down
    # during a lease scan becomes increasingly likely the more shares there
    # are to check.
    last_run = read_time_from_path(last_run_path)
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

    def get_lease_maint_config() -> LeaseMaintenanceConfig:
        return lease_maint_config

    async def maintain_and_record_last_run() -> None:
        try:
            await maintain_leases()
        finally:
            write_time_to_path(
                last_run_path,
                datetime.utcfromtimestamp(reactor.seconds()),
            )

    return _FuzzyTimerService(
        SERVICE_NAME,
        lambda: Deferred.fromCoroutine(maintain_and_record_last_run()),
        initial_interval,
        sample_interval_distribution,
        get_lease_maint_config,
        reactor,
    )


@attr.s(frozen=True)
class LeaseMaintenanceConfig(object):
    """
    Represent the configuration for a lease maintenance service.

    :ivar crawl_interval_mean: The mean time between lease renewal checks.

    :ivar crawl_interval_range: The range of the uniform distribution of lease
        renewal checks (centered on ``interval_mean``).

    :ivar min_lease_remaining: The minimum amount of time remaining to allow
        on a lease without renewing it.
    """

    crawl_interval_mean: timedelta = attr.ib()
    crawl_interval_range: timedelta = attr.ib()
    min_lease_remaining: timedelta = attr.ib()

    @classmethod
    def from_node_config(cls, node_config: Config) -> LeaseMaintenanceConfig:
        """
        Return a ``LeaseMaintenanceConfig`` representing the values from the given
        configuration object.
        """
        return cls(
            crawl_interval_mean=read_duration(
                node_config,
                "lease.crawl-interval.mean",
                timedelta(days=26),
            ),
            crawl_interval_range=read_duration(
                node_config,
                "lease.crawl-interval.range",
                timedelta(days=4),
            ),
            # The greater the min lease remaining time, the more of each lease
            # period is "wasted" by renewing the lease before it has expired.
            # The premise of ZKAPAuthorizer's use of leases is that if they
            # expire, the storage server is free to reclaim the storage by
            # forgetting about the share.  However, since we do not know of
            # any ZKAPAuthorizer-enabled storage grids which will garbage
            # collect shares when leases expire, we have no reason not to use
            # a zero duration here - for now.
            #
            # In the long run, storage servers must run with garbage
            # collection enabled.  Ideally, before that happens, we will have
            # a system that doesn't involve trading of wasted lease time
            # against reliability of leases being renewed before the shares
            # are garbage collected.
            #
            # Also, since this is configuration, you can set it to something
            # else if you want.
            min_lease_remaining=read_duration(
                node_config,
                "lease.min-time-remaining",
                timedelta(days=0),
            ),
        )

    def get_lease_duration(self) -> int:
        """
        Return the minimum amount of time for which a newly granted lease will
        ensure data is stored.

        The actual lease duration is hard-coded in Tahoe-LAFS in many places.
        However, we have local configuration that tells us when to renew a lease.
        Since lease renewal discards any remaining time on a current lease and
        puts a new lease period in its place, starting from the time of the
        operation, the amount of time we effectively get from a lease is based on
        Tahoe-LAFS' hard-coded lease duration and our own lease renewal
        configuration.

        Since this function only promises to return the *minimum* time a client
        can expect a lease to last, we respond with a lease time shortened by our
        configuration.

        An excellent goal to pursue in the future would be to change the lease
        renewal behavior in Tahoe-LAFS so that we can control the length of leases
        and/or add to an existing lease instead of replacing it.  The former
        option would let us really configure lease durations.  The latter would
        let us stop worrying so much about what is lost by renewing a lease before
        the last second of its validity period.

        :return int: The minimum number of seconds for which a newly acquired
            lease will be valid.
        """
        # See lots of places in Tahoe-LAFS, eg src/allmydata/storage/server.py
        upper_bound = 31 * 24 * 60 * 60
        min_time_remaining = self.min_lease_remaining.total_seconds()
        return int(upper_bound - min_time_remaining)


def lease_maintenance_config_to_dict(
    lease_maint_config: LeaseMaintenanceConfig,
) -> dict[str, str]:
    return {
        "lease.crawl-interval.mean": _format_duration(
            lease_maint_config.crawl_interval_mean,
        ),
        "lease.crawl-interval.range": _format_duration(
            lease_maint_config.crawl_interval_range,
        ),
        "lease.min-time-remaining": _format_duration(
            lease_maint_config.min_lease_remaining,
        ),
    }


def _format_duration(td: timedelta) -> str:
    return str(int(td.total_seconds()))


def _parse_duration(duration_str: str) -> timedelta:
    return timedelta(seconds=int(duration_str))


def lease_maintenance_config_from_dict(d: dict[str, str]) -> LeaseMaintenanceConfig:
    return LeaseMaintenanceConfig(
        crawl_interval_mean=_parse_duration(d["lease.crawl-interval.mean"]),
        crawl_interval_range=_parse_duration(d["lease.crawl-interval.range"]),
        min_lease_remaining=_parse_duration(d["lease.min-time-remaining"]),
    )


def write_time_to_path(path: FilePath, when: datetime) -> None:
    """
    Write an ISO8601 datetime string to a file.

    :param path: The path to a file to which to write the datetime string.

    :param when: The datetime to write.
    """
    path.setContent(when.isoformat().encode("utf-8"))  # type: ignore[no-untyped-call]


def read_time_from_path(path: FilePath) -> Optional[datetime]:
    """
    Read an ISO8601 datetime string from a file.

    :param path: The path to a file containing a datetime string.

    :return: None if no file exists at the path.  Otherwise, a datetime
        instance giving the time represented in the file.
    """
    try:
        when = path.getContent()  # type: ignore[no-untyped-call]
    except IOError as e:
        if ENOENT == e.errno:
            return None
        raise
    else:
        result = parse_datetime(when.decode("ascii"))
        assert isinstance(result, datetime)
        return result


def visit_storage_indexes_from_root(
    visit_assets: Callable[[VisitAssets], Awaitable[None]],
    get_root_nodes: Callable[[], list[IFilesystemNode]],
) -> Callable[[], Coroutine[Deferred[None], None, None]]:
    """
    An operation for ``lease_maintenance_service`` which applies the given
    visitor to ``root_node`` and all its children.

    :param visit_assets: A one-argument callable which takes the traversal
        function and which should call it as desired.

    :param get_root_nodes: A no-argument callable which returns a list of
        filesystem nodes (``IFilesystemNode``) at which traversal will begin.

    :return: A no-argument callable to perform the visits.
    """

    async def result() -> None:
        # Make sure we call get_root_nodes each time to give us a chance
        # to notice when it changes.
        roots = get_root_nodes()

        async def bound_visitor(visitor: Visitor) -> None:
            await visit_storage_indexes(roots, visitor)

        await visit_assets(bound_visitor)

    return result


@implementer(ILeaseMaintenanceObserver)
class NoopMaintenanceObserver(object):
    """
    A lease maintenance observer that does nothing.
    """

    def observe(self, sizes: list[int]) -> None:
        pass

    def finish(self) -> None:
        pass


@implementer(ILeaseMaintenanceObserver)
@define
class MemoryMaintenanceObserver(object):
    """
    A lease maintenance observer that records observations in memory.
    """

    observed: list[list[int]] = Factory(list)
    finished: bool = False

    def observe(self, sizes: list[int]) -> None:
        self.observed.append(sizes)

    def finish(self) -> None:
        self.finished = True


def maintain_leases_from_root(
    get_root_nodes: Callable[[], list[IFilesystemNode]],
    storage_broker: StorageFarmBroker,
    secret_holder: SecretHolder,
    min_lease_remaining: timedelta,
    progress: Callable[[], ILeaseMaintenanceObserver],
    get_now: Callable[[], datetime],
) -> Callable[[], Coroutine[Deferred[None], None, None]]:
    """
    An operation for ``lease_maintenance_service`` which visits ``root_node``
    and all its children and renews their leases if they have
    ``min_lease_remaining`` or less on them.

    :param get_root_nodes: A no-argument callable which returns the list of
        Tahoe-LAFS filesystem nodes (``IFilesystemNode``) to use as the roots
        of the node hierarchies to be maintained.

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

    async def visitor(visit_assets: VisitAssets) -> None:
        await renew_leases(
            visit_assets,
            storage_broker,
            secret_holder,
            min_lease_remaining,
            progress,
            get_now,
        )

    return visit_storage_indexes_from_root(
        visitor,
        get_root_nodes,
    )


def calculate_initial_interval(
    sample_interval_distribution: Callable[[], timedelta],
    last_run: datetime,
    now: datetime,
) -> timedelta:
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
