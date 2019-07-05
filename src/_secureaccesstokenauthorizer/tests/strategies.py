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
Hypothesis strategies for property testing.
"""

from hypothesis.strategies import (
    just,
    binary,
    integers,
    sets,
)

from allmydata.interfaces import (
    StorageIndex,
    LeaseRenewSecret,
    LeaseCancelSecret,
)

def configurations():
    """
    Build configuration values for the plugin.
    """
    return just({})


def storage_indexes():
    """
    Build Tahoe-LAFS storage indexes.
    """
    return binary(
        min_size=StorageIndex.minLength,
        max_size=StorageIndex.maxLength,
    )


def lease_renew_secrets():
    """
    Build Tahoe-LAFS lease renewal secrets.
    """
    return binary(
        min_size=LeaseRenewSecret.minLength,
        max_size=LeaseRenewSecret.maxLength,
    )


def lease_cancel_secrets():
    """
    Build Tahoe-LAFS lease cancellation secrets.
    """
    return binary(
        min_size=LeaseCancelSecret.minLength,
        max_size=LeaseCancelSecret.maxLength,
    )


def sharenums():
    """
    Build Tahoe-LAFS share numbers.
    """
    return integers(
        min_value=0,
        max_value=255,
    )


def sharenum_sets():
    """
    Build sets of Tahoe-LAFS share numbers.
    """
    return sets(
        sharenums(),
        min_size=1,
        max_size=255,
    )


def sizes():
    """
    Build Tahoe-LAFS share sizes.
    """
    return integers(
        min_value=0,
        # Just for practical purposes...
        max_value=2 ** 16,
    )
