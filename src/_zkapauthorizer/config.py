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

__all__ = [
    "REPLICA_RWCAP_BASENAME",
    "EmptyConfig",
    "empty_config",
    "read_duration",
    "read_node_url",
]

from datetime import timedelta
from typing import Any, Optional

from allmydata.node import _Config as Config
from attrs import define
from hyperlink import DecodedURL
from twisted.python.filepath import FilePath

from . import NAME

# The basename of the replica read-write capability file in the node's private
# directory, if replication is configured.
REPLICA_RWCAP_BASENAME = NAME + ".replica-rwcap"


@define
class EmptyConfig:
    """
    Weakly pretend to be a Tahoe-LAFS configuration object with no
    configuration.
    """

    _basedir: FilePath = FilePath(".")

    def get_config(self, section, option, default=object(), boolean=False):
        return default

    def get_private_path(self, name):
        return self._basedir.child("private").child(name).path


empty_config = EmptyConfig()


def read_node_url(config: Config) -> DecodedURL:
    """
    Get the root of the node's HTTP API.
    """
    return DecodedURL.from_text(
        FilePath(config.get_config_path("node.url"))
        .getContent()
        .decode("ascii")
        .strip()
    )


def read_duration(cfg: Config, option: str, default: Any) -> Optional[timedelta]:
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
