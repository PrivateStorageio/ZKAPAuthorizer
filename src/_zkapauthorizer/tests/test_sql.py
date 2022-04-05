# coding: utf-8
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
Tests for ``_zkapauthorizer.model``.
"""


from hypothesis import given
from hypothesis.strategies import (
    sampled_from,
    tuples,
)
from testtools import TestCase
from testtools.matchers import (
    Equals,
)

from .strategies import (
    deletes,
    inserts,
    sql_identifiers,
    tables,
    updates,
)
from ..sql import statement_mutates


class MutateTests(TestCase):
    """
    Tests for ``statement_mutates``
    """

    @given(
        tuples(
            sampled_from([inserts, deletes, updates]),
            sql_identifiers(),
            tables(),
        ).flatmap(
            lambda x: x[0](x[1], x[2]),
        )
    )
    def test_mutate(self, change):
        self.assertThat(
            statement_mutates(change.statement()),
            Equals(True),
        )
