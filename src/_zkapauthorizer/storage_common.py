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
    return int(
        ceil(
            sum(share_sizes, 0) / bytes_per_pass,
        ),
    )


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


def get_implied_data_length(data_vector, length):
    """
    :param data_vector: See ``allmydata.interfaces.DataVector``.

    :param length: ``None`` or an overriding value for the length of the data.
        This corresponds to the *new length* in
        ``allmydata.interfaces.TestAndWriteVectorsForShares``.  It may be
        smaller than the result would be considering only ``data_vector`` if
        there is a trunctation or larger if there is a zero-filled extension.

    :return int: The amount of data, in bytes, implied by a data vector and a
        size.
    """
    if length is None:
        return max(
            offset + len(data)
            for (offset, data)
            in data_vector
        )
    return length
