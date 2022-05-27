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
Functionality shared between the storage client and server.
"""

from base64 import b64encode
from typing import Callable, Union, ValuesView

import attr
from pyutil.mathutil import div_ceil

from . import NAME
from .eliot import MUTABLE_PASSES_REQUIRED
from .validators import greater_than


@attr.s(str=True)
class MorePassesRequired(Exception):
    """
    Storage operations fail with ``MorePassesRequired`` when they are not
    accompanied by a sufficient number of valid passes.

    :ivar valid_count: The number of valid passes presented in the operation.

    ivar required_count: The number of valid passes which must be presented
        for the operation to be authorized.

    :ivar signature_check_failed: Indices into the supplied list of passes
        indicating passes which failed the signature check.
    """

    valid_count: int = attr.ib(validator=attr.validators.instance_of(int))
    required_count: int = attr.ib(validator=attr.validators.instance_of(int))
    signature_check_failed: frozenset[int] = attr.ib(converter=frozenset)


def _message_maker(label: str) -> Callable[[bytes], bytes]:
    def make_message(storage_index):
        return "{label} {storage_index}".format(
            label=label,
            storage_index=b64encode(storage_index).decode("ascii"),
        ).encode("ascii")

    return make_message


# Functions to construct the PrivacyPass request-binding message for pass
# construction for different Tahoe-LAFS storage operations.
allocate_buckets_message = _message_maker("allocate_buckets")
add_lease_message = _message_maker("add_lease")
slot_testv_and_readv_and_writev_message = _message_maker(
    "slot_testv_and_readv_and_writev"
)

# The number of bytes we're willing to store for a lease period for each pass
# submitted.
BYTES_PER_PASS = 1024 * 1024


def get_configured_shares_needed(node_config):
    """
    Determine the configured-specified value of "needed" shares (``k``).

    If no value is explicitly configured, the Tahoe-LAFS default (as best as
    we know it) is returned.
    """
    return int(
        node_config.get_config(
            section="client",
            option="shares.needed",
            default=3,
        )
    )


def get_configured_shares_total(node_config):
    """
    Determine the configured-specified value of "total" shares (``N``).

    If no value is explicitly configured, the Tahoe-LAFS default (as best as
    we know it) is returned.
    """
    return int(
        node_config.get_config(
            section="client",
            option="shares.total",
            default=10,
        )
    )


def get_configured_pass_value(node_config):
    """
    Determine the configuration-specified value of a single ZKAP.

    If no value is explicitly configured, a default value is returned.  The
    value is read from the **pass-value** option of the ZKAPAuthorizer plugin
    client section.
    """
    section_name = "storageclient.plugins." + NAME
    return int(
        node_config.get_config(
            section=section_name,
            option="pass-value",
            default=BYTES_PER_PASS,
        )
    )


def get_configured_allowed_public_keys(node_config):
    """
    Read the set of allowed issuer public keys from the given configuration.
    """
    section_name = "storageclient.plugins." + NAME
    return set(
        node_config.get_config(
            section=section_name,
            option="allowed-public-keys",
        )
        .strip()
        .split(",")
    )


_dict_values: type = type(dict().values())


def required_passes(
    bytes_per_pass: int, share_sizes: Union[ValuesView[int], list[int]]
) -> int:
    """
    Calculate the number of passes that are required to store shares of the
    given sizes for one lease period.

    :param bytes_per_pass: The number of bytes the storage of which for one
        lease period one pass covers.

    :param share_sizes: The sizes of the shared which will be stored.

    :return: The number of passes required to cover the storage cost.
    """
    if not isinstance(share_sizes, (list, _dict_values)):
        raise TypeError(
            "Share sizes must be a list (or dict_values) of integers, got {!r} instead".format(
                share_sizes,
            ),
        )
    result, b = divmod(sum(share_sizes, 0), bytes_per_pass)
    if b > 0:
        result += 1

    # print("required_passes({}, {}) == {}".format(bytes_per_pass, share_sizes, result))
    return result


def share_size_for_data(shares_needed, datasize):
    """
    Calculate the size of a single erasure encoding share for data of the
    given size and with the given level of redundancy.

    :param int shares_needed: The number of shares (``k``) from the erasure
        encoding process which are required to reconstruct original data of
        the indicated size.

    :param int datasize: The size of the data to consider, in bytes.

    :return int: The size of a single erasure encoding share for the given
        inputs.
    """
    return div_ceil(datasize, shares_needed)


def has_writes(tw_vectors):
    """
    :param tw_vectors: See
        ``allmydata.interfaces.TestAndWriteVectorsForShares``.

    :return bool: ``True`` if any only if there are writes in ``tw_vectors``.
    """
    return any(
        data or (new_length is not None)
        for (test, data, new_length) in tw_vectors.values()
    )


def get_write_sharenums(tw_vectors):
    """
    :param tw_vectors: See
        ``allmydata.interfaces.TestAndWriteVectorsForShares``.

    :return set[int]: The share numbers which the given test/write vectors would write to.
    """
    return set(
        # This misses cases where `data` is empty but `new_length` is
        # non-None, non-0.
        #
        # Related to #222.
        sharenum
        for (sharenum, (test, data, new_length)) in tw_vectors.items()
        if data
    )


def get_allocated_size(tw_vectors):
    """
    :param tw_vectors: See
        ``allmydata.interfaces.TestAndWriteVectorsForShares``.

    :return int: The largest position ``tw_vectors`` writes in any share.
    """
    return max(
        list(
            max(offset + len(s) for (offset, s) in data)
            for (sharenum, (test, data, new_length)) in tw_vectors.items()
            if data
        ),
    )


def get_implied_data_length(data_vector, new_length):
    """
    :param data_vector: See ``allmydata.interfaces.DataVector``.

    :param new_length: See
        ``allmydata.interfaces.RIStorageServer.slot_testv_and_readv_and_writev``.

    :return int: The amount of data, in bytes, implied by a data vector and a
        size.
    """
    data_based_size = (
        max(offset + len(data) for (offset, data) in data_vector) if data_vector else 0
    )
    if new_length is None:
        return data_based_size
    # new_length is only allowed to truncate, not expand.
    return min(new_length, data_based_size)


def get_required_new_passes_for_mutable_write(pass_value, current_sizes, tw_vectors):
    """
    :param int pass_value: The value of a single pass in byte-months.

    :param current_sizes:
    """
    current_passes = required_passes(
        pass_value,
        current_sizes.values(),
    )

    new_sizes = current_sizes.copy()
    size_updates = {
        sharenum: get_implied_data_length(data_vector, new_length)
        for (sharenum, (_, data_vector, new_length)) in tw_vectors.items()
    }
    for sharenum, size in size_updates.items():
        if size > new_sizes.get(sharenum, 0):
            new_sizes[sharenum] = size

    new_passes = required_passes(
        pass_value,
        new_sizes.values(),
    )
    required_new_passes = new_passes - current_passes

    MUTABLE_PASSES_REQUIRED.log(
        current_sizes=current_sizes,
        tw_vectors_summary=summarize(tw_vectors),
        current_passes=current_passes,
        new_sizes=new_sizes,
        new_passes=new_passes,
    )
    return required_new_passes


def summarize(tw_vectors):
    return {
        sharenum: {
            "testv": list(
                (offset, length, operator, len(specimen))
                for (offset, length, operator, specimen) in test_vector
            ),
            "datav": list((offset, len(data)) for (offset, data) in data_vectors),
            "new_length": new_length,
        }
        for (sharenum, (test_vector, data_vectors, new_length)) in tw_vectors.items()
    }


def pass_value_attribute():
    """
    Define an attribute for an attrs-based object which can hold a pass value.
    """
    return attr.ib(
        validator=attr.validators.and_(
            attr.validators.instance_of(int),
            greater_than(0),
        ),
    )
