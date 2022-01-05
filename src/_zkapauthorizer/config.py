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
Helpers for reading values from the Tahoe-LAFS configuration.
"""

from datetime import timedelta
from typing import Optional

from allmydata.node import _Config

from .lease_maintenance import LeaseMaintenanceConfig


class _EmptyConfig(object):
    """
    Weakly pretend to be a Tahoe-LAFS configuration object with no
    configuration.
    """

    def get_config(self, section, option, default=object(), boolean=False):
        return default


empty_config = _EmptyConfig()


def lease_maintenance_from_tahoe_config(node_config):
    # type: (_Config) -> LeaseMaintenanceConfig
    """
    Return a ``LeaseMaintenanceConfig`` representing the values from the given
    configuration object.
    """
    return LeaseMaintenanceConfig(
        crawl_interval_mean=_read_duration(
            node_config,
            u"lease.crawl-interval.mean",
            timedelta(days=26),
        ),
        crawl_interval_range=_read_duration(
            node_config,
            u"lease.crawl-interval.range",
            timedelta(days=4),
        ),
        # The greater the min lease remaining time, the more of each lease
        # period is "wasted" by renewing the lease before it has expired.  The
        # premise of ZKAPAuthorizer's use of leases is that if they expire,
        # the storage server is free to reclaim the storage by forgetting
        # about the share.  However, since we do not know of any
        # ZKAPAuthorizer-enabled storage grids which will garbage collect
        # shares when leases expire, we have no reason not to use a zero
        # duration here - for now.
        #
        # In the long run, storage servers must run with garbage collection
        # enabled.  Ideally, before that happens, we will have a system that
        # doesn't involve trading of wasted lease time against reliability of
        # leases being renewed before the shares are garbage collected.
        #
        # Also, since this is configuration, you can set it to something else
        # if you want.
        min_lease_remaining=_read_duration(
            node_config,
            u"lease.min-time-remaining",
            timedelta(days=0),
        ),
    )


def get_configured_lease_duration(node_config):
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
    lease_maint_config = lease_maintenance_from_tahoe_config(node_config)
    min_time_remaining = lease_maint_config.min_lease_remaining.total_seconds()
    return int(upper_bound - min_time_remaining)


def _read_duration(cfg, option, default):
    """
    Read an integer number of seconds from the ZKAPAuthorizer section of a
    Tahoe-LAFS config.

    :param cfg: The Tahoe-LAFS config object to consult.
    :param option: The name of the option to read.

    :return: ``None`` if the option is missing, otherwise the parsed duration
        as a ``timedelta``.
    """
    # type: (_Config, str) -> Optional[timedelta]
    section_name = u"storageclient.plugins.privatestorageio-zkapauthz-v1"
    value_str = cfg.get_config(
        section=section_name,
        option=option,
        default=None,
    )
    if value_str is None:
        return default
    return timedelta(seconds=int(value_str))
