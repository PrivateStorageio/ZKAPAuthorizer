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

from __future__ import (
    absolute_import,
    unicode_literals,
)

from datetime import (
    datetime,
    timedelta,
)

import attr

from testtools import (
    TestCase,
)
from testtools.matchers import (
    Equals,
)
from testtools.twistedsupport import (
    succeeds,
)
from hypothesis import (
    given,
    note,
)
from hypothesis.strategies import (
    builds,
    binary,
    integers,
    lists,
    floats,
    dictionaries,
    randoms,
)

from twisted.internet.task import (
    Clock,
)
from twisted.internet.defer import (
    succeed,
)
from twisted.application.service import (
    IService,
)

from allmydata.util.hashutil import (
    CRYPTO_VAL_SIZE,
)
from allmydata.client import (
    SecretHolder,
)

from ..foolscap import (
    ShareStat,
)

from .matchers import (
    Provides,
    between,
)
from .strategies import (
    storage_indexes,
    clocks,
    node_hierarchies,
)

from ..lease_maintenance import (
    lease_maintenance_service,
    maintain_leases_from_root,
)


def interval_means():
    return floats(
        # It doesn't make sense to have a negative check interval mean.
        min_value=0,
        # We can't make this value too large or it isn't convertable to a
        # timedelta.  Also, even values as large as this one are of
        # questionable value.
        max_value=60 * 60 * 24 * 365,
    ).map(
        # By representing the result as a timedelta we avoid the cases where
        # the lower precision of timedelta compared to float drops the whole
        # value (anything between 0 and 1 microsecond).  This is just on
        # example of how working with timedeltas is nicer, in general.
        lambda s: timedelta(seconds=s),
    )


def dummy_maintain_leases():
    pass


@attr.s
class DummyStorageServer(object):
    """
    :ivar dict[bytes, datetime] buckets: A mapping from storage index to lease
        expiration time for shares at that storage index.
    """
    clock = attr.ib()
    buckets = attr.ib()
    lease_seed = attr.ib()

    def stat_shares(self, storage_indexes):
        return succeed(list(
            self.buckets[idx]
            for idx
            in storage_indexes
        ))

    def get_lease_seed(self):
        return self.lease_seed

    def renew_lease(self, storage_index, renew_secret):
        self.buckets[storage_index].lease_expiration = (
            self.clock.seconds() + timedelta(days=31).total_seconds()
        )


def lease_seeds():
    return binary(
        min_size=CRYPTO_VAL_SIZE,
        max_size=CRYPTO_VAL_SIZE,
    )

def share_stats():
    return builds(
        ShareStat,
        size=integers(min_value=0),
        lease_expiration=integers(min_value=0, max_value=2 ** 31),
    )

def storage_servers(clocks):
    return builds(
        DummyStorageServer,
        clocks,
        dictionaries(storage_indexes(), share_stats()),
        lease_seeds(),
    )


@attr.s
class DummyStorageBroker(object):
    clock = attr.ib()
    _storage_servers = attr.ib()

    def get_connected_servers(self):
        return self._storage_servers


def storage_brokers(clocks):
    return builds(
        DummyStorageBroker,
        lists(storage_servers(clocks)),
    )


class LeaseMaintenanceServiceTests(TestCase):
    """
    Tests for the service returned by ``lease_maintenance_service``.
    """
    @given(randoms())
    def test_interface(self, random):
        """
        The service provides ``IService``.
        """
        clock = Clock()
        service = lease_maintenance_service(
            dummy_maintain_leases,
            clock,
            None,
            random,
        )
        self.assertThat(
            service,
            Provides([IService]),
        )

    @given(
        randoms(),
        interval_means(),
    )
    def test_initial_interval(self, random, mean):
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
            None,
            random,
            mean,
            range_,
        )
        service.startService()
        [maintenance_call] = clock.getDelayedCalls()

        datetime_now = datetime.utcfromtimestamp(clock.seconds())
        low = datetime_now + mean - (range_ / 2)
        high = datetime_now + mean + (range_ / 2)
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
    def test_initial_interval_with_last_run(self, random, clock, mean, since_last_run):
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

        service = lease_maintenance_service(
            dummy_maintain_leases,
            clock,
            last_run,
            random,
            mean,
            range_,
        )
        service.startService()
        [maintenance_call] = clock.getDelayedCalls()

        low = datetime_now + max(
            timedelta(0),
            mean - (range_ / 2) - since_last_run,
        )
        high = max(
            # If since_last_run is one microsecond (precision of timedelta)
            # then the range is indivisible.  Avoid putting the expected high
            # below the expected low.
            low,
            datetime_now + mean + (range_ / 2) - since_last_run,
        )

        note("mean: {}\nrange: {}\nnow: {}\nlow: {}\nhigh: {}\nsince last: {}".format(
            mean, range_, datetime_now, low, high, since_last_run,
        ))

        self.assertThat(
            datetime.utcfromtimestamp(maintenance_call.getTime()),
            between(low, high),
        )

    @given(
        randoms(),
        clocks(),
    )
    def test_nodes_visited(self, random, clock):
        """
        When the service runs, it calls the ``maintain_leases`` object.
        """
        leases_maintained_at = []
        def maintain_leases():
            leases_maintained_at.append(datetime.utcfromtimestamp(clock.seconds()))

        service = lease_maintenance_service(
            maintain_leases,
            clock,
            None,
            random,
        )
        service.startService()
        [maintenance_call] = clock.getDelayedCalls()
        clock.advance(maintenance_call.getTime() - clock.seconds())

        self.assertThat(
            leases_maintained_at,
            Equals([datetime.utcfromtimestamp(clock.seconds())]),
        )


class MaintainLeasesFromRootTests(TestCase):
    """
    Tests for ``maintain_leases_from_root``.
    """
    @given(node_hierarchies(), clocks())
    def test_visits_all_nodes(self, root_node, clock):
        """
        The operation calls the specified visitor with every node from the root to
        its deepest children.
        """
        visited = []
        def visitor(node):
            visited.append(node)

        storage_broker = DummyStorageBroker(clock, [])
        secret_holder = SecretHolder(lease_secret, convergence_secret)

        operation = maintain_leases_from_root(
            visitor,
            root_node,
            storage_broker,
            secret_holder,
            timedelta(days=3),
            lambda: datetime.utcfromtimestamp(clock.seconds()),
        )

        self.assertThat(
            operation(root_node),
            succeeds(Always()),
        )
