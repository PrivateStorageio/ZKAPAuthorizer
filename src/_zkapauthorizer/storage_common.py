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

from __future__ import (
    division,
)

from base64 import (
    b64encode,
)

from math import (
    ceil,
)

def _message_maker(label):
    def make_message(storage_index):
        return u"{label} {storage_index}".format(
            label=label,
            storage_index=b64encode(storage_index),
        )
    return make_message

# Functions to construct the PrivacyPass request-binding message for pass
# construction for different Tahoe-LAFS storage operations.
allocate_buckets_message = _message_maker(u"allocate_buckets")
add_lease_message = _message_maker(u"add_lease")
renew_lease_message = _message_maker(u"renew_lease")
slot_testv_and_readv_and_writev_message = _message_maker(u"slot_testv_and_readv_and_writev")

# The number of bytes we're willing to store for a lease period for each pass
# submitted.
BYTES_PER_PASS = 128 * 1024

def required_passes(bytes_per_pass, share_sizes):
    """
    Calculate the number of passes that are required to store ``stored_bytes``
    for one lease period.

    :param int bytes_per_pass: The number of bytes the storage of which for
        one lease period one pass covers.

    :param set[int] share_sizes: The sizes of the shared which will be stored.

    :return int: The number of passes required to cover the storage cost.
    """
    result = int(
        ceil(
            sum(share_sizes, 0) / bytes_per_pass,
        ),
    )
    # print("required_passes({}, {}) == {}".format(bytes_per_pass, share_sizes, result))
    return result


def has_writes(tw_vectors):
    """
    :param tw_vectors: See
        ``allmydata.interfaces.TestAndWriteVectorsForShares``.

    :return bool: ``True`` if any only if there are writes in ``tw_vectors``.
    """
    return any(
        data or (new_length is not None)
        for (test, data, new_length)
        in tw_vectors.values()
    )


def get_sharenums(tw_vectors):
    """
    :param tw_vectors: See
        ``allmydata.interfaces.TestAndWriteVectorsForShares``.

    :return set[int]: The share numbers which the given test/write vectors would write to.
    """
    return set(
        sharenum
        for (sharenum, (test, data, new_length))
        in tw_vectors.items()
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
            for (sharenum, (test, data, new_length))
            in tw_vectors.items()
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
    data_based_size = max(
        offset + len(data)
        for (offset, data)
        in data_vector
    ) if data_vector else 0
    if new_length is None:
        return data_based_size
    # new_length is only allowed to truncate, not expand.
    return min(new_length, data_based_size)


def get_required_new_passes_for_mutable_write(current_sizes, tw_vectors):
    # print("get_required_new_passes_for_mutable_write({}, {})".format(current_sizes, summarize(tw_vectors)))
    current_passes = required_passes(
        BYTES_PER_PASS,
        current_sizes.values(),
    )

    new_sizes = current_sizes.copy()
    size_updates = {
        sharenum: get_implied_data_length(data_vector, new_length)
        for (sharenum, (_, data_vector, new_length))
        in tw_vectors.items()
    }
    for sharenum, size in size_updates.items():
        if size > new_sizes.get(sharenum, 0):
            new_sizes[sharenum] = size

    new_sizes.update()
    new_passes = required_passes(
        BYTES_PER_PASS,
        new_sizes.values(),
    )
    required_new_passes = new_passes - current_passes

    # print("Current sizes: {}".format(current_sizes))
    # print("Current passes: {}".format(current_passes))
    # print("New sizes: {}".format(new_sizes))
    # print("New passes: {}".format(new_passes))
    return required_new_passes

def summarize(tw_vectors):
    return {
        sharenum: (
            test_vector,
            list(
                (offset, len(data))
                for (offset, data)
                in data_vectors
            ),
            new_length,
        )
        for (sharenum, (test_vector, data_vectors, new_length))
        in tw_vectors.items()
    }
