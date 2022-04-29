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


import sqlite3

from hypothesis import given
from hypothesis.strategies import sampled_from, tuples
from testtools import TestCase
from testtools.matchers import Equals

from ..sql import bind_arguments, statement_mutates
from .strategies import deletes, inserts, selects, sql_identifiers, tables, updates


class BindTests(TestCase):
    """
    Tests for ``bind_arguments``
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
        conn = sqlite3.connect(":memory:")
        cursor = conn.cursor()
        self.assertThat(
            bind_arguments(cursor, change.statement(), change.arguments()),
            Equals(change.bound_statement(cursor)),
        )


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

    @given(
        tuples(sampled_from([selects]), sql_identifiers(),).flatmap(
            lambda x: x[0](x[1]),
        )
    )
    def test_non_mutate(self, change):
        self.assertThat(
            statement_mutates(change.statement()),
            Equals(False),
        )
