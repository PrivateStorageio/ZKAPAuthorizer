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

try:
    from typing import Optional
except ImportError:
    pass

from .lease_maintenance import LeaseMaintenanceConfig

from allmydata.node import _Config

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
