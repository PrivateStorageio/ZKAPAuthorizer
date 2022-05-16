# coding: utf-8
# Copyright 2022 PrivateStorage.io, LLC
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
Tests for ``_zkapauthorizer.sql``.
"""


from hypothesis import given
from hypothesis.strategies import sampled_from, tuples
from testtools import TestCase
from testtools.matchers import Equals

from ..sql import statement_mutates
from .strategies import deletes, inserts, selects, sql_identifiers, tables, updates

mutations = tuples(
    sampled_from([inserts, deletes, updates]),
    sql_identifiers(),
    tables(),
).flatmap(
    lambda x: x[0](x[1], x[2]),
)


class MutateTests(TestCase):
    """
    Tests for ``statement_mutates``
    """

    @given(mutations)
    def test_mutate(self, change) -> None:
        """
        ``statement_mutates`` returns True for SQL INSERT, DELETE, and UPDATE
        statements.
        """
        self.assertThat(
            statement_mutates(change.statement()),
            Equals(True),
        )

    @given(
        tuples(sampled_from([selects]), sql_identifiers()).flatmap(
            lambda x: x[0](x[1]),
        )
    )
    def test_non_mutate(self, change) -> None:
        """
        ``statement_mutates`` returns False for SQL SELECT and BEGIN IMMEDIATE
        TRANSACTION statements.
        """
        self.assertThat(
            statement_mutates(change.statement()),
            Equals(False),
        )
        self.assertThat(
            statement_mutates("BEGIN IMMEDIATE TRANSACTION"),
            Equals(False),
        )
