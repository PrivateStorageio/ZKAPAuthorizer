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

from __future__ import (
    unicode_literals,
)

"""
This module defines the database schema used by the model interface.
"""

def get_schema_version(cursor):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS [version] AS SELECT 0 AS [version]
        """
    )
    cursor.execute(
        """
        SELECT [version] FROM [version]
        """
    )
    [(actual_version,)] = cursor.fetchall()
    return actual_version


def get_schema_upgrades(from_version):
    """
    Generate unicode strings containing SQL expressions to alter a schema from
    ``from_version`` to the latest version.

    :param int from_version: The version of the schema which may require
        upgrade.
    """
    while from_version in _UPGRADES:
        for upgrade in _UPGRADES[from_version]:
            yield upgrade
        yield _INCREMENT_VERSION
        from_version += 1


def run_schema_upgrades(upgrades, cursor):
    """
    Apply the given upgrades using the given cursor.

    :param list[unicode] upgrades: The SQL statements to apply for the
        upgrade.

    :param cursor: A DB-API cursor to use to run the SQL.
    """
    for upgrade in upgrades:
        cursor.execute(upgrade)


_INCREMENT_VERSION = (
    """
    UPDATE [version]
    SET [version] = [version] + 1
    """
)

# A mapping from old schema versions to lists of unicode strings of SQL to
# execute against that version of the schema to create the successor schema.
_UPGRADES = {
    0: [
        """
        CREATE TABLE [vouchers] (
            [number] text,
            [created] text,                     -- An ISO8601 date+time string.
            [state] text DEFAULT "pending",     -- pending, double-spend, redeemed

            [finished] text DEFAULT NULL,       -- ISO8601 date+time string when
                                                -- the current terminal state was entered.

            [token-count] num DEFAULT NULL,     -- Set in the redeemed state to the number
                                                -- of tokens received on this voucher's
                                                -- redemption.

            PRIMARY KEY([number])
        )
        """,
        """
        CREATE TABLE [tokens] (
            [text] text, -- The random string that defines the token.
            [voucher] text, -- Reference to the voucher these tokens go with.

            PRIMARY KEY([text])
            FOREIGN KEY([voucher]) REFERENCES [vouchers]([number])
        )
        """,
        """
        CREATE TABLE [unblinded-tokens] (
            [token] text, -- The base64 encoded unblinded token.

            PRIMARY KEY([token])
        )
        """,
        """
        CREATE TABLE [lease-maintenance-spending] (
            [id] integer, -- A unique identifier for a group of activity.
            [started] text, -- ISO8601 date+time string when the activity began.
            [finished] text, -- ISO8601 date+time string when the activity completed (or null).

            -- The number of passes that would be required to renew all
            -- shares encountered during this activity.  Note that because
            -- leases on different shares don't necessarily expire at the
            -- same time this is not necessarily the number of passes
            -- **actually** used during this activity.  Some shares may
            -- not have required lease renewal.  Also note that while the
            -- activity is ongoing this value may change.
            [count] integer,

            PRIMARY KEY([id])
        )
        """,
    ],

    1: [
        """
        ALTER TABLE [vouchers] ADD COLUMN [public-key] text
        """,
    ],

    2: [
        """
        -- Keep track of progress through redemption of each voucher.
        ALTER TABLE [vouchers] ADD COLUMN [counter] integer DEFAULT 0
        """,
    ],

    3: [
        """
        -- Reference to the counter these tokens go with.
        ALTER TABLE [tokens] ADD COLUMN [counter] integer NOT NULL DEFAULT 0
        """,
        """
        -- Record the total number of tokens for which we expect to be able to
        -- redeem this voucher.  We don't want to allow NULL values here at
        -- all because that allows insertion of garbage data going forward.
        -- However to add a non-NULL column to a table we have to supply a
        -- default value.  Since no real vouchers have ever been issued at the
        -- time of this upgrade we'll just make up some value.  It doesn't
        -- particularly matter if it is wrong for some testing voucher someone
        -- used.
        ALTER TABLE [vouchers] ADD COLUMN [expected-tokens] integer NOT NULL DEFAULT 32768
        """,
    ],
}
