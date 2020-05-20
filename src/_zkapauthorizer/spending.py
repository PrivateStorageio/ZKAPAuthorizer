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
A module for logic controlling the manner in which ZKAPs are spent.
"""

import attr

from .eliot import (
    GET_PASSES,
)


@attr.s
class SpendingController(object):
    """
    A ``SpendingController`` gives out ZKAPs and arranges for re-spend
    attempts when necessary.
    """
    extract_unblinded_tokens = attr.ib()
    tokens_to_passes = attr.ib()

    def get(self, message, num_passes):
        unblinded_tokens = self.extract_unblinded_tokens(num_passes)
        passes = self.tokens_to_passes(message, unblinded_tokens)
        GET_PASSES.log(
            message=message,
            count=num_passes,
        )
        return passes
