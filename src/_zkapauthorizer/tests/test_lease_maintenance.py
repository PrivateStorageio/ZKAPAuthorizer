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
Tests for ``_zkapauthorizer.lease_maintenance``.
"""

from datetime import datetime, timedelta
from random import Random
from typing import Callable, Sequence, TypeVar

from allmydata.client import SecretHolder
from allmydata.interfaces import (
    IDirectoryNode,
    IFilesystemNode,
    IServer,
    IStorageBroker,
)
from allmydata.util.hashutil import CRYPTO_VAL_SIZE
from attrs import define
from fixtures import TempDir
from hypothesis import given, note
from hypothesis.strategies import (
    SearchStrategy,
    binary,
    builds,
    dictionaries,
    integers,
    just,
    lists,
    randoms,
    sets,
)
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    AllMatch,
    Always,
    Equals,
    HasLength,
    Is,
    MatchesAll,
)
from testtools.twistedsupport import succeeded
from twisted.application.service import IService
from twisted.internet.defer import Deferred, maybeDeferred, succeed
from twisted.internet.task import Clock
from twisted.python.filepath import FilePath
from zope.interface import implementer

from ..config import Config, empty_config
from ..foolscap import ShareStat
from ..lease_maintenance import (
    LeaseMaintenanceConfig,
    MemoryMaintenanceObserver,
    NoopMaintenanceObserver,
    StorageIndex,
    VisitAssets,
    lease_maintenance_config_from_dict,
    lease_maintenance_config_to_dict,
    lease_maintenance_service,
    maintain_leases_from_root,
    renew_leases,
    visit_storage_indexes_from_root,
)
from .common import DummyStorageServer
from .matchers import Provides, between, leases_current
from .strategies import (
    clocks,
    interval_means,
    lease_maintenance_configurations,
    node_hierarchies,
    posix_timestamps,
    sharenums,
    storage_indexes,
)

default_lease_maint_config = LeaseMaintenanceConfig.from_node_config(empty_config)


async def dummy_maintain_leases() -> None:
    pass


class SharesAlreadyExist(Exception):
    pass


def create_share(
    storage_server: DummyStorageServer,
    storage_index: bytes,
    sharenum: int,
    size: int,
    lease_expiration: int,
) -> None:
    """
    Add a share to a storage index ("bucket").

    :param storage_server: The server to populate with shares.
    :param storage_index: The storage index of the shares.
    :param sharenum: The share number to add.
    :param size: The application data size of the shares.
    :param lease_expiration: The expiration time for the lease to attach to
        the shares.

    :raise SharesAlreadyExist: If there are already shares at the given
        storage index.

    :return: ``None``
    """
    if sharenum in storage_server.buckets.get(storage_index, {}):
        raise SharesAlreadyExist(
            "Cannot create shares for storage index where they already exist.",
        )
    bucket = storage_server.buckets.setdefault(storage_index, {})
    bucket[sharenum] = ShareStat(
        size=size,
        lease_expiration=lease_expiration,
    )


def lease_seeds() -> SearchStrategy[bytes]:
    return binary(
        min_size=20,
        max_size=20,
    )


def share_stats() -> SearchStrategy[ShareStat]:
    return builds(
        ShareStat,
        size=integers(min_value=0),
        lease_expiration=integers(min_value=0, max_value=2**31),
    )


@implementer(IServer)
@define
class DummyServer(object):
    """
    A partial implementation of a Tahoe-LAFS "native" storage server.
    """

    _storage_server: DummyStorageServer

    def get_storage_server(self) -> DummyStorageServer:
        return self._storage_server


def storage_servers(
    clocks: SearchStrategy[Clock],
) -> SearchStrategy[DummyServer]:
    return builds(
        DummyStorageServer,
        clocks,
        dictionaries(storage_indexes(), dictionaries(sharenums(), share_stats())),
        lease_seeds(),
    ).map(
        DummyServer,
    )


@implementer(IStorageBroker)
@define
class DummyStorageBroker(object):
    """
    A partial implementation of a Tahoe-LAFS storage broker.
    """

    clock: Clock
    _storage_servers: list[IServer]

    def get_connected_servers(self) -> Sequence[IServer]:
        return self._storage_servers


def storage_brokers(
    clocks: SearchStrategy[Clock],
) -> SearchStrategy[DummyStorageBroker]:
    def build_storage_servers(clock: Clock) -> SearchStrategy[DummyStorageBroker]:
        def make_broker(servers: list[DummyServer]) -> DummyStorageBroker:
            return DummyStorageBroker(clock, servers)

        return lists(storage_servers(just(clock))).map(make_broker)

    return clocks.flatmap(build_storage_servers)


class LeaseMaintenanceConfigTests(TestCase):
    """
    Tests related to ``LeaseMaintenanceConfig``.
    """

    @given(lease_maintenance_configurations())
    def test_config_roundtrip(self, config: Config) -> None:
        """
        ``LeaseMaintenanceConfig`` round-trips through
        ``lease_maintenance_config_to_dict`` and
        ``lease_maintenance_config_from_dict``.
        """
        dumped = lease_maintenance_config_to_dict(config)
        loaded = lease_maintenance_config_from_dict(dumped)
        self.assertThat(loaded, Equals(config))


class LeaseMaintenanceServiceTests(TestCase):
    """
    Tests for the service returned by ``lease_maintenance_service``.
    """

    @given(randoms())
    def test_interface(self, random: Random) -> None:
        """
        The service provides ``IService``.
        """
        clock = Clock()
        service = lease_maintenance_service(
            dummy_maintain_leases,
            clock,
            FilePath(self.useFixture(TempDir()).join("last-run")),
            random,
            lease_maint_config=default_lease_maint_config,
        )
        self.assertThat(
            service,
            Provides([IService]),
        )

    @given(
        randoms(),
        interval_means(),
    )
    def test_initial_interval(self, random: Random, mean: timedelta) -> None:
        """
        When constructed without a value for ``last_run``,
        ``lease_maintenance_service`` schedules its first run to take place
        after an interval that falls uniformly in range centered on ``mean``
        with a size of ``range``.
        """
        clock = Clock()
        # Construct a range that fits in with the mean
        range_ = timedelta(
            seconds=random.uniform(0, mean.total_seconds()),
        )

        service = lease_maintenance_service(
            dummy_maintain_leases,
            clock,
            FilePath(self.useFixture(TempDir()).join("last-run")),
            random,
            LeaseMaintenanceConfig(
                mean,
                range_,
                timedelta(0),
            ),
        )
        service.startService()
        [maintenance_call] = clock.getDelayedCalls()

        datetime_now = datetime.utcfromtimestamp(clock.seconds())
        low = datetime_now + mean - (range_ // 2)
        high = datetime_now + mean + (range_ // 2)
        self.assertThat(
            datetime.utcfromtimestamp(maintenance_call.getTime()),
            between(low, high),
        )

    @given(
        randoms(),
        clocks(),
        interval_means(),
        interval_means(),
    )
    def test_initial_interval_with_last_run(
        self, random: Random, clock: Clock, mean: timedelta, since_last_run: timedelta
    ) -> None:
        """
        When constructed with a value for ``last_run``,
        ``lease_maintenance_service`` schedules its first run to take place
        sooner than it otherwise would, by at most the time since the last
        run.
        """
        datetime_now = datetime.utcfromtimestamp(clock.seconds())
        # Construct a range that fits in with the mean
        range_ = timedelta(
            seconds=random.uniform(0, mean.total_seconds()),
        )

        # Figure out the absolute last run time.
        last_run = datetime_now - since_last_run
        last_run_path = FilePath(self.useFixture(TempDir()).join("last-run"))
        last_run_path.setContent(last_run.isoformat().encode("utf-8"))

        service = lease_maintenance_service(
            dummy_maintain_leases,
            clock,
            last_run_path,
            random,
            LeaseMaintenanceConfig(
                mean,
                range_,
                timedelta(0),
            ),
        )
        service.startService()
        [maintenance_call] = clock.getDelayedCalls()

        low = datetime_now + max(
            timedelta(0),
            mean - (range_ // 2) - since_last_run,
        )
        high = max(
            # If since_last_run is one microsecond (precision of timedelta)
            # then the range is indivisible.  Avoid putting the expected high
            # below the expected low.
            low,
            datetime_now + mean + (range_ // 2) - since_last_run,
        )

        note(
            "mean: {}\nrange: {}\nnow: {}\nlow: {}\nhigh: {}\nsince last: {}".format(
                mean,
                range_,
                datetime_now,
                low,
                high,
                since_last_run,
            )
        )

        self.assertThat(
            datetime.utcfromtimestamp(maintenance_call.getTime()),
            between(low, high),
        )

    @given(
        randoms(),
        clocks(),
    )
    def test_clean_up_when_stopped(self, random: Random, clock: Clock) -> None:
        """
        When the service is stopped, the delayed call in the reactor is removed.
        """

        async def maintain_leases() -> None:
            pass

        service = lease_maintenance_service(
            maintain_leases,
            clock,
            FilePath(self.useFixture(TempDir()).join("last-run")),
            random,
            lease_maint_config=default_lease_maint_config,
        )
        service.startService()
        self.assertThat(
            maybeDeferred(service.stopService),
            succeeded(Is(None)),
        )
        self.assertThat(
            clock.getDelayedCalls(),
            Equals([]),
        )
        self.assertThat(
            service.running,
            Equals(False),
        )

    @given(
        randoms(),
        clocks(),
    )
    def test_nodes_visited(self, random: Random, clock: Clock) -> None:
        """
        When the service runs, it calls the ``maintain_leases`` object.
        """
        leases_maintained_at = []

        async def maintain_leases() -> None:
            leases_maintained_at.append(datetime.utcfromtimestamp(clock.seconds()))

        service = lease_maintenance_service(
            maintain_leases,
            clock,
            FilePath(self.useFixture(TempDir()).join("last-run")),
            random,
            lease_maint_config=default_lease_maint_config,
        )
        service.startService()
        [maintenance_call] = clock.getDelayedCalls()
        clock.advance(maintenance_call.getTime() - clock.seconds())

        self.assertThat(
            leases_maintained_at,
            Equals([datetime.utcfromtimestamp(clock.seconds())]),
        )


class VisitStorageIndexesFromRootTests(TestCase):
    """
    Tests for ``visit_storage_indexes_from_root``.
    """

    @given(node_hierarchies(), clocks())
    def test_visits_all_nodes(self, root_node: IDirectoryNode, clock: Clock) -> None:
        """
        The operation calls the specified visitor with every node from the root to
        its deepest children.
        """
        visited: list[bytes] = []

        async def perform_visit(visit_assets: VisitAssets) -> None:
            return await visit_assets(visited.append)

        operation = visit_storage_indexes_from_root(
            perform_visit,
            lambda: [root_node],
        )

        self.assertThat(
            Deferred.fromCoroutine(operation()),
            succeeded(Always()),
        )
        expected = root_node.flatten()
        self.assertThat(
            visited,
            MatchesAll(
                HasLength(len(expected)),
                AfterPreprocessing(
                    set,
                    Equals(set(node.get_storage_index() for node in expected)),
                ),
            ),
        )


T = TypeVar("T")
S = TypeVar("S")


def lists_of_buckets() -> SearchStrategy[list[tuple[StorageIndex, dict[int, float]]]]:
    """
    Build lists of bucket descriptions.

    A bucket description is a two-tuple of a storage index and a dict mapping
    share numbers to lease expiration times (as posix timestamps).  Any given
    storage index will appear only once in the overall result.
    """

    def add_expiration_times(
        sharenums: set[int],
    ) -> SearchStrategy[dict[int, list[float]]]:
        return builds(
            lambda nums, expires: dict(zip(nums, expires)),
            just(sharenums),
            lists(
                posix_timestamps(),
                min_size=len(sharenums),
                max_size=len(sharenums),
            ),
        )

    def buckets_strategy(
        count: int,
    ) -> SearchStrategy[list[tuple[StorageIndex, dict[int, float]]]]:

        si_strategy: SearchStrategy[set[bytes]] = sets(
            storage_indexes(),
            min_size=count,
            max_size=count,
        )

        shares_with_expiration: SearchStrategy[dict[int, list[float]]] = sets(
            sharenums(),
            min_size=1,
        ).flatmap(add_expiration_times)

        sharenum_strategy: SearchStrategy[list[dict[int, list[float]]]] = lists(
            shares_with_expiration,
            min_size=count,
            max_size=count,
        )

        return builds(
            zip,  # type: ignore[arg-type]
            si_strategy,
            sharenum_strategy,
        )

    bucket_count_strategy = integers(min_value=0, max_value=100)
    return bucket_count_strategy.flatmap(buckets_strategy)


class RenewLeasesTests(TestCase):
    """
    Tests for ``renew_leases``.
    """

    @given(storage_brokers(clocks()), lists_of_buckets())
    def test_renewed(
        self,
        storage_broker: DummyStorageBroker,
        buckets: list[tuple[StorageIndex, dict[int, float]]],
    ) -> None:
        """
        ``renew_leases`` renews the leases of shares on all storage servers which
        have no more than the specified amount of time remaining on their
        current lease.
        """
        lease_secret = b"\0" * CRYPTO_VAL_SIZE
        convergence_secret = b"\1" * CRYPTO_VAL_SIZE
        secret_holder = SecretHolder(lease_secret, convergence_secret)
        min_lease_remaining = timedelta(days=3)

        # Make sure that the storage brokers have shares at the storage
        # indexes we're going to operate on.
        for storage_server in storage_broker.get_connected_servers():
            for (storage_index, shares) in buckets:
                for sharenum, expiration_time in shares.items():
                    try:
                        create_share(
                            storage_server.get_storage_server(),
                            storage_index,
                            sharenum,
                            size=123,
                            lease_expiration=int(expiration_time),
                        )
                    except SharesAlreadyExist:
                        # If the storage_brokers() strategy already put a
                        # share at this location, that's okay too.
                        pass

        def get_now() -> datetime:
            return datetime.utcfromtimestamp(
                storage_broker.clock.seconds(),
            )

        def visit_assets(visit: Callable[[StorageIndex], None]) -> Deferred[None]:
            for storage_index, ignored in buckets:
                visit(storage_index)
            return succeed(None)

        d = renew_leases(
            visit_assets,
            storage_broker,
            secret_holder,
            min_lease_remaining,
            NoopMaintenanceObserver,
            get_now,
        )
        self.assertThat(
            Deferred.fromCoroutine(d),
            succeeded(Always()),
        )

        self.assertThat(
            list(
                server.get_storage_server()
                for server in storage_broker.get_connected_servers()
            ),
            AllMatch(
                leases_current(
                    list(storage_index for (storage_index, ignored) in buckets),
                    get_now(),
                    min_lease_remaining,
                )
            ),
        )


class MaintainLeasesFromRootTests(TestCase):
    """
    Tests for ``maintain_leases_from_root``.
    """

    @given(storage_brokers(clocks()), node_hierarchies())
    def test_renewed(
        self, storage_broker: DummyStorageBroker, root_node: IFilesystemNode
    ) -> None:
        """
        ``maintain_leases_from_root`` creates an operation which renews the leases
        of shares on all storage servers which have no more than the specified
        amount of time remaining on their current lease.
        """
        lease_secret = b"\0" * CRYPTO_VAL_SIZE
        convergence_secret = b"\1" * CRYPTO_VAL_SIZE
        secret_holder = SecretHolder(lease_secret, convergence_secret)
        min_lease_remaining = timedelta(days=3)

        def get_now() -> datetime:
            return datetime.utcfromtimestamp(
                storage_broker.clock.seconds(),
            )

        operation = maintain_leases_from_root(
            lambda: [root_node],
            storage_broker,
            secret_holder,
            min_lease_remaining,
            NoopMaintenanceObserver,
            get_now,
        )
        d = operation()
        self.assertThat(
            Deferred.fromCoroutine(d),
            succeeded(Always()),
        )

        relevant_storage_indexes = set(
            node.get_storage_index() for node in root_node.flatten()
        )

        self.assertThat(
            list(
                server.get_storage_server()
                for server in storage_broker.get_connected_servers()
            ),
            AllMatch(
                leases_current(
                    relevant_storage_indexes,
                    get_now(),
                    min_lease_remaining,
                )
            ),
        )

    @given(storage_brokers(clocks()), node_hierarchies())
    def test_activity_observed(
        self, storage_broker: DummyStorageBroker, root_node: IFilesystemNode
    ) -> None:
        """
        ``maintain_leases_from_root`` creates an operation which uses the given
        activity observer to report its progress.
        """
        lease_secret = b"\0" * CRYPTO_VAL_SIZE
        convergence_secret = b"\1" * CRYPTO_VAL_SIZE
        secret_holder = SecretHolder(lease_secret, convergence_secret)
        min_lease_remaining = timedelta(days=3)

        def get_now() -> datetime:
            return datetime.utcfromtimestamp(
                storage_broker.clock.seconds(),
            )

        observer = MemoryMaintenanceObserver()
        # There is only one available.
        observers = [observer]
        progress = observers.pop
        operation = maintain_leases_from_root(
            lambda: [root_node],
            storage_broker,
            secret_holder,
            min_lease_remaining,
            progress,
            get_now,
        )
        d = operation()
        self.assertThat(
            Deferred.fromCoroutine(d),
            succeeded(Always()),
        )

        expected = []
        for node in root_node.flatten():
            for server in storage_broker.get_connected_servers():
                try:
                    shares = server.get_storage_server().buckets[
                        node.get_storage_index()
                    ]
                except KeyError:
                    continue
                else:
                    if shares:
                        expected.append(list(stat.size for stat in shares.values()))

        # The visit order doesn't matter.
        expected.sort()

        self.assertThat(
            observer.observed,
            AfterPreprocessing(
                sorted,
                Equals(expected),
            ),
        )
