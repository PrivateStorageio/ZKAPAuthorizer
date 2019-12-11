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
from hypothesis.strategies import (
    builds,
    binary,
    integers,
    lists,
    dictionaries,
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
)
from .strategies import (
    storage_indexes,
)

from ..lease_maintenace import (
    lease_maintenance_service,
)


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
    def test_interface(self):
        """
        The service provides ``IService``.
        """
        clock = Clock()
        root_node = object()
        random = object()
        lease_secret = b"\0" * CRYPTO_VAL_SIZE
        convergence_secret = b"\1" * CRYPTO_VAL_SIZE
        service = lease_maintenance_service(
            clock,
            root_node,
            DummyStorageBroker(clock, []),
            SecretHolder(lease_secret, convergence_secret),
            datetime.utcfromtimestamp(0),
            random,
        )
        self.assertThat(
            service,
            Provides(IService),
        )
