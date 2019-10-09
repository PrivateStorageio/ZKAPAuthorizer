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

def required_passes(bytes_per_pass, share_nums, share_size):
    """
    Calculate the number of passes that are required to store ``stored_bytes``
    for one lease period.

    :param int bytes_per_pass: The number of bytes the storage of which for
        one lease period one pass covers.

    :param set[int] share_nums: The share numbers which will be stored.
    :param int share_size: THe number of bytes in a single share.

    :return int: The number of passes required to cover the storage cost.
    """
    return int(
        ceil(
            (len(share_nums) * share_size) / bytes_per_pass,
        ),
    )
