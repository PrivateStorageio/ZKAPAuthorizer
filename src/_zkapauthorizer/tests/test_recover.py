"""
Tests for ``_zkapauthorizer.recover``, the replication recovery system.
"""

from sqlite3 import Connection, connect
from typing import Dict

from hypothesis import assume, note, settings
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)
from hypothesis.strategies import data, lists, randoms, sampled_from
from testtools import TestCase
from testtools.matchers import AfterPreprocessing, Equals

from .._sql import Table, create_table
from ..recover import MemorySnapshotRecoverer, RecoveryStages
from .strategies import deletes, inserts, sql_identifiers, tables, updates


def snapshot(connection: Connection):
    for statement in connection.iterdump():
        note("iterdump: {!r}".format(statement))
        yield statement + "\n"


def equals_db(reference):
    return AfterPreprocessing(
        lambda actual: list(actual.iterdump()),
        Equals(list(reference.iterdump())),
    )


class SnapshotMachine(RuleBasedStateMachine):
    """
    Transition rules for a state machine corresponding to the state of a
    SQLite3 database.  Transitions are schema changes, row inserts, row
    updates, row deletions, etc.
    """

    def __init__(self, case):
        super().__init__()
        self.case = case
        self.connection = connect(":memory:")

        self.tables: Dict[str, Table] = {}

    @invariant()
    def snapshot_equals_database(self):
        """
        At all points a snapshot of the database can be used to construct a new
        database with the same contents.
        """
        statements = list(snapshot(self.connection))
        new = connect(":memory:")
        recoverer = MemorySnapshotRecoverer(statements)
        recoverer.recover(new)
        self.case.assertThat(
            recoverer.state().stage,
            Equals(RecoveryStages.succeeded),
        )

        self.case.assertThat(
            new,
            equals_db(reference=self.connection),
            "source (reference) database iterdump does not equal "
            "sink (actual) database iterdump",
        )

    @rule(
        name=sql_identifiers(),
        table=tables(),
    )
    def create_table(self, name, table):
        """
        Create a new table in the database.
        """
        assume(name not in self.tables)
        self.tables[name] = table
        statement = create_table(name, table)
        note("executing {!r}".format(statement))
        self.connection.execute(statement)

    @precondition(lambda self: len(self.tables) > 0)
    @rule(
        change_types=lists(sampled_from([inserts, deletes, updates]), min_size=1),
        random=randoms(),
        data=data(),
    )
    def modify_rows(self, change_types, random, data):
        """
        Change some rows in some tables.
        """

        for change_type in change_types:
            # Choose a table to impact
            table_name = random.choice(sorted(self.tables))
            # Construct the change
            changes = data.draw(lists(change_type(table_name, self.tables[table_name])))
            # Execute the changes
            for change in changes:
                note(
                    "executing {!r} {!r}".format(change.statement(), change.arguments())
                )
                self.connection.execute(change.statement(), change.arguments())


class SnapshotTests(TestCase):
    """
    Tests for recovery from a database snapshot in a local file.
    """

    def test_snapshots(self):
        run_state_machine_as_test(
            lambda: SnapshotMachine(self),
            settings=settings(
                # Many shallow runs are probably more useful than fewer deep
                # runs.  That is, exercise breadth in preference to depth.
                max_examples=1000,
                stateful_step_count=5,
            ),
        )
