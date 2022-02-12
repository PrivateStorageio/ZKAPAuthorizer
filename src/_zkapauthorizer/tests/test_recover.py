"""
Tests for ``_zkapauthorizer.recover``, the replication recovery system.
"""

from io import StringIO
from sqlite3 import Connection, connect
from typing import Callable, Dict

from allmydata.node import config_from_string
from attrs import Factory, define, field
from fixtures import TempDir
from hypothesis import assume, given, note, settings
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)
from hypothesis.strategies import data, lists, randoms, sampled_from, text
from testtools import TestCase
from testtools.matchers import AfterPreprocessing, Always, Equals, IsInstance
from testtools.twistedsupport import failed, succeeded
from twisted.internet.defer import Deferred
from twisted.python.filepath import FilePath
from zope.interface import implementer

from .._sql import Table, create_table
from ..recover import (
    AlreadyRecovering,
    BrokenRecoverer,
    IRecoverer,
    ISynchronousRecoverer,
    MemorySnapshotRecoverer,
    NullRecoverer,
    RecoveryStages,
    StatefulRecoverer,
    SynchronousStorageSnapshotRecoverer,
    TahoeLAFSRecoverer,
)
from .strategies import deletes, inserts, sql_identifiers, tables, updates


def snapshot(connection: Connection):
    for statement in connection.iterdump():
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

    def __init__(self, case, make_recoverer):
        super().__init__()
        self.case = case
        self.connection = connect(":memory:")
        self.make_recoverer = make_recoverer

        self.tables: Dict[str, Table] = {}

    @invariant()
    def snapshot_equals_database(self):
        """
        At all points a snapshot of the database can be used to construct a new
        database with the same contents.
        """
        statements = list(snapshot(self.connection))
        new = connect(":memory:")
        recoverer = self.make_recoverer(statements)

        state = None

        def set_state(new_state):
            nonlocal state
            state = new_state

        recoverer.recover(set_state, None, new)
        self.case.assertThat(
            state.stage,
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


def run_snapshot_machine(
    case: TestCase, make_recoverer: Callable[[], ISynchronousRecoverer]
) -> None:
    """
    Run ``SnapshotMachine`` as a unit test.
    """
    # Many shallow runs are probably more useful than fewer deep runs.  That
    # is, exercise breadth in preference to depth.
    #
    # Also try to play along with any profile that has been loaded.
    max_examples = settings.default.max_examples * 10
    stateful_step_count = int(max(1, settings.default.stateful_step_count / 10))

    run_state_machine_as_test(
        lambda: SnapshotMachine(case, make_recoverer),
        settings=settings(
            max_examples=max_examples,
            stateful_step_count=stateful_step_count,
        ),
    )


class MemorySnapshotRecovererTests(TestCase):
    """
    Tests for ``MemorySnapshotRecoverer``.
    """

    def test_snapshots(self):
        """
        Test the snapshot/recovery system using a ``MemorySnapshotRecoverer``.
        """
        run_snapshot_machine(self, MemorySnapshotRecoverer)


@implementer(IRecoverer)
@define
class _AsyncRecovererWrapper:
    """
    Adapt ``ISynchronousRecoverer`` to ``IRecoverer``.
    """

    _wrapped: ISynchronousRecoverer

    async def recover(self, set_state, cap, cursor):
        self._wrapped.recover(set_state, cap, cursor)


class RecovererTestsMixin:
    """
    A mixin defining interface tests that any ``IRecoverer`` implementation
    should pass.
    """

    def upload(self, data: bytes) -> str:
        raise NotImplementedError()

    def make_recoverer(self, cap: str) -> IRecoverer:
        raise NotImplementedError()

    def test_recover(self):
        """
        ````IRecoverer.recover`` loads statements from its path into the cursor
        given.
        """
        statements = [
            # Some DDL
            "CREATE TABLE [foo] ( [a] INT );",
            # Some DML
            "INSERT INTO [foo] ([a]) VALUES (1);",
        ]

        # Construct a database we can use to create a snapshot.
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            for statement in statements:
                cursor.execute(statement)

            snapshot_statements = list(snapshot(conn))

        # Create the object under test - the recoverer which can recover from
        # this snapshot.
        recoverer = self.make_recoverer()

        # Put the snapshot somewhere the recoverer will be able to find it.
        cap = self.upload(("\n".join(snapshot_statements) + "\n").encode("ascii"))

        # Create a database we can recover the snapshot into.
        with connect(":memory:") as conn:
            cursor = conn.cursor()

            self.assertThat(
                # Do the recovery.
                Deferred.fromCoroutine(
                    recoverer.recover(lambda state: None, cap, cursor),
                ),
                succeeded(Always()),
            )
            # A snapshot of the recovered database should be the same as a
            # snapshot of the original.
            self.assertThat(
                list(snapshot(conn)),
                Equals(snapshot_statements),
            )


@define
class MemoryGrid:
    _counter: int = 0
    _snapshots: Dict[str, str] = field(default=Factory(dict))

    def upload(self, data: bytes) -> str:
        cap = str(self._counter)
        self._snapshots[cap] = data
        self._counter += 1
        return cap

    def download(self, cap: str) -> bytes:
        return self._snapshots[cap]


class SynchronousStorageSnapshotRecovererTests(TestCase, RecovererTestsMixin):
    """
    Tests for ``SynchronousStorageSnapshotRecoverer``.
    """

    def setUp(self):
        super().setUp()
        self.grid = MemoryGrid()
        self.upload = self.grid.upload

    def make_recoverer(self) -> SynchronousStorageSnapshotRecoverer:
        """
        Create a ``SynchronousStorageSnapshotRecoverer`` that resolves
        capabilities from the ``MemoryGrid``.
        """

        def open_from_grid(cap):
            return StringIO(self.grid.download(cap).decode("ascii"))

        # FilesystemSnapshotRecoverer is an ISynchronousRecoverer so wrap it
        # up to make it look like an IRecoverer.  This doesn't actually make
        # it asynchronous, of course, but makes the interfaces line up.
        return _AsyncRecovererWrapper(
            SynchronousStorageSnapshotRecoverer(
                open_from_grid,
            ),
        )


class NoSuchCapability(Exception):
    pass


class TahoeLAFSRecovererTests(TestCase, RecovererTestsMixin):
    """
    Tests for ``TahoeLAFSRecoverer``.
    """

    def setUp(self):
        super().setUp()
        self.grid = MemoryGrid()
        self.upload = self.grid.upload
        self.node_dir = FilePath(self.useFixture(TempDir()).join("node"))
        self.node_dir.child("private").makedirs()

    def make_recoverer(self) -> TahoeLAFSRecoverer:
        """
        Create a ``TahoeLAFSRecoverer`` which can see an immutable object
        containing the given statements.
        """

        async def download(client, outpath, api_root, cap):
            try:
                obj = self.grid.download(cap)
            except KeyError:
                raise NoSuchCapability()
            else:
                outpath.setContent(obj)

        # treq is used by the real download function but we're supplying our
        # own that doesn't need it, so value here should be irrelevant.  maybe
        # the http client should be implied by the download API rather than a
        # parameter it accepts?
        treq = object()
        node_config = config_from_string(self.node_dir.path, "", "")
        return TahoeLAFSRecoverer(treq, node_config, download)

    def test_recover_failed(self):
        """
        If the snapshot data cannot be found then ``IRecoverer.recover`` raises
        the underlying exception.
        """
        recoverer = self.make_recoverer()

        # Just invent a capability.  There will be no associated data and so
        # recovery will fail.
        cap = "abcdef"

        states = []
        record_state = states.append

        with connect(":memory:") as conn:
            cursor = conn.cursor()
            # We expect the recoverer to fail with the exception raised by the
            # downloader for now.  Later we probably want it to inspect the
            # exception and sometimes take a different action.  It will
            # probably never recognize our test-only NoSuchCapability
            # exception though.
            self.assertThat(
                Deferred.fromCoroutine(
                    recoverer.recover(record_state, cap, cursor),
                ),
                failed(
                    AfterPreprocessing(
                        lambda f: f.value,
                        IsInstance(NoSuchCapability),
                    ),
                ),
            )


class StatefulRecovererTests(TestCase):
    """
    Tests for ``StatefulRecoverer``.
    """

    @given(text())
    def test_succeeded_after_recover(self, cap):
        """
        ``StatefulRecoverer`` automatically progresses to the succeeded stage when
        the wrapped recoverer completes without exception.
        """
        recoverer = StatefulRecoverer(NullRecoverer())
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            first = Deferred.fromCoroutine(recoverer.recover(cap, cursor))
            self.assertThat(
                first,
                succeeded(Always()),
            )
            self.assertThat(
                recoverer.state().stage,
                Equals(RecoveryStages.succeeded),
            )

    @given(text())
    def test_failed_after_recover(self, cap):
        """
        ``StatefulRecoverer`` automatically progresses to the failed stage when
        the wrapped recoverer completes with an exception.
        """
        recoverer = StatefulRecoverer(BrokenRecoverer())
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            first = Deferred.fromCoroutine(recoverer.recover(cap, cursor))
            self.assertThat(
                first,
                succeeded(Always()),
            )
            self.assertThat(recoverer.state().stage, Equals(RecoveryStages.failed))

    @given(text())
    def test_cannot_recover_twice(self, cap):
        """
        A second call to ``StatefulRecoverer.recover`` fails with
        ``AlreadyRecovering``.
        """
        recoverer = StatefulRecoverer(NullRecoverer())
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            self.assertThat(
                Deferred.fromCoroutine(recoverer.recover(cap, cursor)),
                succeeded(Always()),
            )
            second = Deferred.fromCoroutine(recoverer.recover(cap, cursor))
            self.assertThat(
                second,
                failed(
                    AfterPreprocessing(
                        lambda f: f.value,
                        IsInstance(AlreadyRecovering),
                    ),
                ),
            )
