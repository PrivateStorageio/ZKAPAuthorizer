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
Tests for ``_zkapauthorizer.schema``.
"""

from datetime import datetime, timezone
from typing import Optional

from fixtures import TempDir
from hypothesis import assume, given
from hypothesis.strategies import SearchStrategy
from hypothesis.strategies import datetimes as naive_datetimes
from hypothesis.strategies import integers, none, one_of
from testtools import TestCase
from testtools.matchers import Equals

from ..model import memory_connect
from ..schema import _UPGRADES, get_schema_upgrades, get_schema_version


def datetimes() -> SearchStrategy[datetime]:
    """
    Build naive datetime instances that represent times that actually happened
    or will actually happen bounded within a pretty reasonable range around
    when this code was written.
    """
    return naive_datetimes(
        allow_imaginary=False,
        # The software has not existing very long.  There is no point going
        # very far back in time.  Also, according to authorities, timezones
        # are basically meaningless before 1900 anyway.
        min_value=datetime(1995, 1, 1, 0, 0),
        # Similarly, this upgrade is going to happen so going very far into
        # the future is also less interresting.  Also, the behavior of
        # calendars and clocks becomes harder to predict the further you go.
        # In particular, things fall apart around "spring forward" in 2038 - I
        # suppose because SQLite3 can't figure out the DST rules for any point
        # after 2 ** 31 - 1 seconds after the POSIX epoch.
        max_value=datetime(2038, 1, 1, 0, 0),
    )


class UpgradeTests(TestCase):
    def test_consistency(self) -> None:
        """
        Upgrades are defined for every version up to the latest version.
        """
        self.assertThat(
            list(_UPGRADES.keys()),
            Equals(list(range(len(_UPGRADES)))),
        )

    @given(
        datetimes(),
        one_of(none(), datetimes()),
        integers(min_value=0, max_value=2**63 - 1),
    )
    def test_utc_datetimes(
        self, start: datetime, finish: Optional[datetime], count: int
    ) -> None:
        """
        The schema upgrades naive, localtime timestamps from before schema version
        7 to UTC timestamps.
        """
        # a datetime instance can be "folded".  When the clock seems to rewind
        # by an hour for DST, all of the times in that hour will seem to
        # repeat.  A datetime with fold=1 represents the 2nd time.  Since this
        # distinction is not present in the database, it is guaranteed that
        # only one or the other case can work here.  The information is lost
        # so there's nothing we can do to fix it.  We could make it an error
        # but that seems bad.  Otherwise, we can arbitrarily pick one
        # interpretation or the other.  That choice is basically up to SQLite3
        # since we're using it to do the conversion to UTC.  It happens to
        # interpret is as the first occurrance rather than the second.  So,
        # prevent the test from running with the other kind of value.
        #
        # https://docs.python.org/3/library/datetime.html#datetime.datetime.fold
        assume(not start.fold)
        assume(finish is None or not finish.fold)

        dbpath = self.useFixture(TempDir()).join("utc_datetimes")
        with memory_connect(dbpath) as conn:
            cursor = conn.cursor()
            for upgrade in get_schema_upgrades(get_schema_version(cursor)):
                cursor.execute(upgrade)
                if get_schema_version(cursor) == 6:
                    # Stop here so we can populate the database with some
                    # state that requires upgrade.
                    break

            cursor.execute(
                """
                INSERT INTO [lease-maintenance-spending] ([started], [finished], [count])
                VALUES (?, ?, ?)
                """,
                (start, finish, count),
            )

            # Finish the upgrade
            for upgrade in get_schema_upgrades(get_schema_version(cursor)):
                cursor.execute(upgrade)

            cursor.execute(
                """
                SELECT [started], [finished], [count]
                FROM [lease-maintenance-spending]
                """
            )
            actual_start, actual_finished, actual_count = cursor.fetchone()

            def expected_datetime(value):
                return (
                    value.replace(
                        # The schema upgrade throws away sub-second precision.
                        # Perhaps not ideal but in practice it doesn't matter.
                        microsecond=0
                    )
                    # Translate the naive local time into an aware UTC-zoned
                    # value.
                    .astimezone(timezone.utc).isoformat(" ")
                )

            expected_start = expected_datetime(start)
            if finish is None:
                expected_finish = None
            else:
                expected_finish = expected_datetime(finish)

            self.assertThat(
                (actual_start, actual_finished, actual_count),
                Equals((expected_start, expected_finish, count)),
            )
