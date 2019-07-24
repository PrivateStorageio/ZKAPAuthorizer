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
This module implements models (in the MVC sense) for the client side of
the storage plugin.
"""

from os import (
    makedirs,
)
from errno import (
    EEXIST,
)
from json import (
    loads,
    dumps,
)
import attr

# XXX
from allmydata.node import (
    _Config,
    MissingConfigEntry,
)

class StoreAddError(Exception):
    def __init__(self, reason):
        self.reason = reason


class StoreDirectoryError(Exception):
    def __init__(self, reason):
        self.reason = reason


@attr.s(frozen=True)
class PaymentReferenceStore(object):
    """
    This class implements persistence for payment references.

    :ivar _Config node_config: The Tahoe-LAFS node configuration object for
        the node that owns the persisted payment preferences.
    """
    _CONFIG_DIR = u"privatestorageio-satauthz-v1"
    node_config = attr.ib(type=_Config)

    def _config_key(self, prn):
        return u"{}/{}.prn+json".format(self._CONFIG_DIR, prn)

    def _read_pr_json(self, prn):
        private_config_item = self._config_key(prn)
        try:
            return self.node_config.get_private_config(private_config_item)
        except MissingConfigEntry:
            raise KeyError(prn)

    def _write_pr_json(self, prn, pr_json):
        private_config_item = self._config_key(prn)
        # XXX Need an API to be able to avoid touching the filesystem directly
        # here.
        container = self.node_config.get_private_path(self._CONFIG_DIR)
        try:
            makedirs(container)
        except EnvironmentError as e:
            if EEXIST != e.errno:
                raise StoreDirectoryError(e)
        try:
            self.node_config.write_private_config(private_config_item, pr_json)
        except Exception as e:
            raise StoreAddError(e)

    def get(self, prn):
        payment_reference_json = self._read_pr_json(prn)
        return PaymentReference.from_json(payment_reference_json)

    def add(self, prn):
        # XXX Not *exactly* atomic is it?  Probably want a
        # write_private_config_if_not_exists or something.
        try:
            self._read_pr_json(prn)
        except KeyError:
            self._write_pr_json(prn, PaymentReference(prn).to_json())


@attr.s
class PaymentReference(object):
    number = attr.ib()

    @classmethod
    def from_json(cls, json):
        values = loads(json)
        version = values.pop(u"version")
        return getattr(cls, "from_json_v{}".format(version))(values)


    @classmethod
    def from_json_v1(cls, values):
        return cls(**values)


    def to_json(self):
        return dumps(self.to_json_v1())


    def to_json_v1(self):
        result = attr.asdict(self)
        result[u"version"] = 1
        return result
