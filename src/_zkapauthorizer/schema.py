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


_INCREMENT_VERSION = """
    UPDATE [version]
    SET [version] = [version] + 1
    """

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
        -- Incorrectly track a single public-key for all.  Later version of
        -- the schema moves this elsewhere.
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
    4: [
        """
        CREATE TABLE [invalid-unblinded-tokens] (
            [token] text,  -- The base64 encoded unblinded token.
            [reason] text, -- The reason given for it being considered invalid.

            PRIMARY KEY([token])
        )
        """,
    ],
    5: [
        """
        -- Create a table where rows represent a single group of unblinded
        -- tokens all redeemed together.  Some number of these rows represent
        -- a complete redemption of a voucher.
        CREATE TABLE [redemption-groups] (
            -- A unique identifier for this redemption group.
            [rowid] INTEGER PRIMARY KEY,

            -- The text representation of the voucher this group is associated with.
            [voucher] text,

            -- A flag indicating whether these tokens can be spent or if
            -- they're being held for further inspection.
            [spendable] integer,

            -- The public key seen when redeeming this group.
            [public-key] text
        )
        """,
        """
        -- Create one redemption group for every existing, redeemed voucher.
        -- These tokens were probably *not* all redeemed in one group but
        -- we've only preserved one public key for them so we can't do much
        -- better than this.
        INSERT INTO [redemption-groups] ([voucher], [public-key], [spendable])
            SELECT DISTINCT([number]), [public-key], 1 FROM [vouchers] WHERE [state] = "redeemed"
        """,
        """
        -- Give each voucher a count of "sequestered" tokens.  Currently,
        -- these are unspendable tokens that were issued using a disallowed
        -- public key.
        ALTER TABLE [vouchers] ADD COLUMN [sequestered-count] integer NOT NULL DEFAULT 0
        """,
        """
        -- Give each unblinded token a reference to the [redemption-groups]
        -- table identifying the group that token arrived with.  This lets us
        -- act collectively on tokens from these groups and identify tokens
        -- which are spendable.
        --
        -- The default value is provided for rows that
        -- existed prior to this upgrade which had no group association.  For
        -- unblinded tokens to exist at all there must be at least one voucher
        -- in the vouchers table.  [redemption-groups] will therefore have at
        -- least one row added to it (by the statement a few lines above).
        -- Note that SQLite3 rowid numbering begins at 1.
        ALTER TABLE [unblinded-tokens] ADD COLUMN [redemption-group] integer DEFAULT 1
        """,
    ],
    6: [
        """
        -- track the "event-stream" which are a series of SQL statements
        -- that modify the database -- except statements which modify this table
        --
        -- Note that 'AUTOINCREMENT' is required to create the
        -- 'sqlite_sequence' table, upon which we depend to discover the
        -- next sequence number
        CREATE TABLE [event-stream] (
            -- A sequence number which allows us to identify specific positions in
            -- the sequence of modifications which were made to the database.
            [sequence-number] INTEGER PRIMARY KEY AUTOINCREMENT,

            -- A SQL statement which likely made a change to the database state.
            [statement] TEXT,

            -- True if this statement was deemed "important" when recorded
            [important] BOOL
        )
        """,
    ],
    7: [
        # Original rows inserted into the vouchers table used naive datetime
        # values serialized with no timezone information.  These values are
        # all in the system's localtime (or at least, whatever the local time
        # was when they were created - that information is lost, though).
        # Convert them to UTC and add a timezone marker for compatibility with
        # new code and to avoid further information loss.
        #
        # We can do this with the builtin SQLite3 datetime function and string
        # concatenation.  Note in particular:
        #
        #     "utc" assumes that the time value to its left is in the local
        #     timezone and adjusts that time value to be in UTC.
        #
        # This conversion will do weird stuff for times arbitrarily far in the
        # past or the future because timezones are hard.  Since there should
        # be no real values to upgrade that are very far in the past or the
        # future, we'll just accept that.
        #
        # https://www.sqlite.org/lang_datefunc.html
        """
        UPDATE [vouchers]
        SET [created] = datetime([created], "utc") || "+00:00"
        """,
        """
        UPDATE [lease-maintenance-spending]
        SET [started] = datetime([started], "utc") || "+00:00"
        """,
        """
        UPDATE [lease-maintenance-spending]
        SET [finished] = datetime([finished], "utc") || "+00:00"
        WHERE [finished] IS NOT NULL
        """,
    ],
    8: [
        # Arguments were originally bound into the statement but this was
        # found to be problematic.  Now they live in this separate column.
        # The default value is the CBOR serialization of an empty sequence.
        """
        ALTER TABLE [event-stream] ADD COLUMN [serialized_arguments] TEXT DEFAULT X'80'
        """,
    ],
}
