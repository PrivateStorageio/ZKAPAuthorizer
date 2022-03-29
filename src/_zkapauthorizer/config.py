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
from typing import Any, TypeVar, Union

from allmydata.node import _Config
from hyperlink import DecodedURL
from twisted.python.filepath import FilePath

from . import NAME

_T = TypeVar("_T")

# The basename of the replica read-write capability file in the node's private
# directory, if replication is configured.
REPLICA_RWCAP_BASENAME = NAME + ".replica-rwcap"


class _EmptyConfig(object):
    """
    Weakly pretend to be a Tahoe-LAFS configuration object with no
    configuration.
    """

    def get_config(self, section, option, default=object(), boolean=False):
        return default


empty_config = _EmptyConfig()


def read_node_url(config: _Config) -> DecodedURL:
    """
    Get the root of the node's HTTP API.
    """
    return DecodedURL.from_text(
        FilePath(config.get_config_path("node.url"))
        .getContent()
        .decode("ascii")
        .strip()
    )


def read_duration(cfg: _Config, option: str, default: _T) -> Union[timedelta, _T]:
    """
    Read an integer number of seconds from the ZKAPAuthorizer section of a
    Tahoe-LAFS config.

    :param cfg: The Tahoe-LAFS config object to consult.
    :param option: The name of the option to read.

    :return: ``None`` if the option is missing, otherwise the parsed duration
        as a ``timedelta``.
    """
    section_name = "storageclient.plugins." + NAME
    value_str = cfg.get_config(
        section=section_name,
        option=option,
        default=None,
    )
    if value_str is None:
        return default
    return timedelta(seconds=int(value_str))
