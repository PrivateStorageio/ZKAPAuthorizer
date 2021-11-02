# -*- coding: utf-8 -*-
# Copyright 2020 PrivateStorage.io, LLC
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
Calculate the price, in ZKAPs, for storing files.

The underlying storage system operates only on individual shares.  Thus, it
*does not* use this file-oriented calculator.  However, for end-users,
file-oriented pricing is often more helpful.  This calculator builds on the
share-oriented price calculation to present file-oriented price information.

It accounts for erasure encoding data expansion.  It does not account for the
real state of the storage system (e.g., if some data is *already* stored then
storing it "again" is essentially free but this will not be reflected by this
calculator).
"""

import attr

from .storage_common import required_passes, share_size_for_data


@attr.s
class PriceCalculator(object):
    """
    :ivar int _shares_needed: The number of shares which are required to
        reconstruct the original data.

    :ivar int _shares_total: The total number of shares which will be
        produced in the erasure encoding process.

    :ivar int _pass_value: The bytes component of the bytes×time value of a
        single pass.
    """

    _shares_needed = attr.ib()
    _shares_total = attr.ib()
    _pass_value = attr.ib()

    def calculate(self, sizes):
        """
        Calculate the price to store data of the given sizes for one lease
        period.

        :param [int] sizes: The sizes of the individual data items in bytes.

        :return int: The number of ZKAPs required.
        """
        share_sizes = (share_size_for_data(self._shares_needed, size) for size in sizes)
        all_required_passes = (
            required_passes(self._pass_value, [share_size] * self._shares_total)
            for share_size in share_sizes
        )
        price = sum(all_required_passes, 0)
        return price
