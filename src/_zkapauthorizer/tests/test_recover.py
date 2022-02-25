"""
Tests for ``_zkapauthorizer.recover``, the replication recovery system.
"""

from asyncio import run
from sqlite3 import Connection, connect
from sys import float_info
from typing import Dict, Iterator

from allmydata.client import read_config
from fixtures import TempDir
from hypothesis import assume, given, note, settings
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)
from hypothesis.strategies import data, lists, randoms, sampled_from
from testresources import setUpResources, tearDownResources
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    Equals,
    IsInstance,
    MatchesStructure,
    Mismatch,
)
from testtools.twistedsupport import AsynchronousDeferredRunTest, failed, succeeded
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.python.filepath import FilePath

from ..config import REPLICA_RWCAP_BASENAME
from ..recover import (
    AlreadyRecovering,
    RecoveryStages,
    ReplicationAlreadySetup,
    StatefulRecoverer,
    attenuate_writecap,
    get_tahoe_lafs_downloader,
    make_canned_downloader,
    make_fail_downloader,
    noop_downloader,
    recover,
    setup_tahoe_lafs_replication,
)
from ..tahoe import MemoryGrid, Tahoe, link, make_directory, upload
from .fixtures import Treq
from .matchers import matches_capability
from .resources import client_manager
from .sql import Table, create_table, escape
from .strategies import (
    api_auth_tokens,
    deletes,
    inserts,
    sql_identifiers,
    tables,
    tahoe_configs,
    updates,
)


def snapshot(connection: Connection) -> Iterator[str]:
    """
    Take a snapshot of the database reachable via the given connection.
    """
    for statement in connection.iterdump():
        yield statement + "\n"


def equals_db(reference: Connection):
    """
    :return: A matcher for a SQLite3 connection to a database with the same
        state as the reference connection's database.
    """

    def structured_dump(db):
        tables = list(structured_dump_tables(db))
        for (name, sql) in tables:
            yield sql
            yield from structured_dump_table(db, name)

    def structured_dump_tables(db):
        curs = db.cursor()
        curs.execute(
            """
            SELECT [name], [sql]
            FROM [sqlite_master]
            WHERE [sql] NOT NULL and [type] == 'table'
            ORDER BY [name]
            """
        )
        yield from iter(curs)

    def structured_dump_table(db, table_name):
        curs = db.cursor()
        curs.execute(f"PRAGMA table_info({escape(table_name)})")

        columns = list(
            (name, type_) for (cid, name, type_, notnull, dftl_value, pk) in list(curs)
        )
        column_names = ", ".join(escape(name) for (name, type_) in columns)
        curs.execute(
            f"""
            SELECT {column_names}
            FROM {escape(table_name)}
            """
        )

        for rows in iter(lambda: curs.fetchmany(1024), []):
            for row in rows:
                yield "INSERT", table_name, row

    return AfterPreprocessing(
        lambda actual: list(structured_dump(actual)),
        _EqualsEnough(list(structured_dump(reference))),
    )


class _EqualsEnough:
    def __init__(self, reference):
        self.reference = reference

    def match(self, actual):
        def compare_row(n, actual, reference):
            if actual[:1] == ("INSERT",):
                actual_name, actual_row = actual[1:]
                reference_name, reference_row = reference[1:]
                if actual_name != reference_name:
                    return Mismatch(
                        "Row {} table name {} != {}".format(
                            n, actual_name, reference_name
                        )
                    )
                if len(actual_row) != len(reference_row):
                    return Mismatch(
                        "Row {} length {} != {}".format(
                            n, len(actual_row), len(reference_row)
                        )
                    )
                for (actual_field, reference_field) in zip(actual_row, reference_row):
                    if isinstance(actual_field, float):
                        if abs(actual_field - reference_field) > float_info.epsilon:
                            return Mismatch(
                                "Row {} float {} too far from reference {}".format(
                                    n, actual_field, reference_field
                                )
                            )
            else:
                if actual != reference:
                    return Mismatch(
                        "Row {} fields {} != {}".format(n, actual, reference)
                    )

        for n, (a, r) in enumerate(zip(actual, self.reference)):
            mismatch = compare_row(n, a, r)
            if mismatch is not None:
                return mismatch


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
        recover(statements, new)
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
                statement = change.statement()
                args = change.arguments()
                note("executing {!r} {!r}".format(statement, args))
                self.connection.execute(statement, args)


class StatefulRecoverTests(TestCase):
    """
    Stateful tests for ``recover``.
    """

    @reproduce_failure(
        "6.37.0", b"AXicY2BkYGAAYxDBwAykmEAcRpAgM1gYpgIJHGSAKGZgAAALiwDc"
    )
    def test_recover(self):
        """
        Test the snapshot/recovery system using ``SnapshotMachine``.
        """
        # Many shallow runs are probably more useful than fewer deep runs.
        # That is, exercise breadth in preference to depth.
        #
        # Also try to play along with any profile that has been loaded.
        max_examples = settings.default.max_examples * 10
        stateful_step_count = int(max(3, settings.default.stateful_step_count / 10))

        run_state_machine_as_test(
            lambda: SnapshotMachine(self),
            settings=settings(
                max_examples=max_examples,
                stateful_step_count=stateful_step_count,
            ),
        )


class StatefulRecovererTests(TestCase):
    """
    Tests for ``StatefulRecoverer``.
    """

    def test_succeeded_after_recover(self):
        """
        ``StatefulRecoverer`` automatically progresses to the succeeded stage when
        recovery completes without exception.
        """
        recoverer = StatefulRecoverer()
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            first = Deferred.fromCoroutine(recoverer.recover(noop_downloader, cursor))
            self.assertThat(
                first,
                succeeded(Always()),
            )
            self.assertThat(
                recoverer.state(),
                MatchesStructure(
                    stage=Equals(RecoveryStages.succeeded),
                ),
            )

    def test_state_recovered(self):
        """
        After ``StatefulRecoverer`` reaches the ``succeeded`` state the state
        represented by the downloaded snapshot is present in the database
        itself.
        """
        snapshot = (
            b"CREATE TABLE [succeeded] ( [a] TEXT );\n"
            b"INSERT INTO [succeeded] ([a]) VALUES ('yes');\n"
        )
        downloader = make_canned_downloader(snapshot)
        recoverer = StatefulRecoverer()
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            first = Deferred.fromCoroutine(recoverer.recover(downloader, cursor))
            self.assertThat(first, succeeded(Always()))

            cursor.execute("SELECT * FROM [succeeded]")
            self.assertThat(
                cursor.fetchall(),
                Equals([("yes",)]),
            )

    def test_failed_after_download_failed(self):
        """
        ``StatefulRecoverer`` automatically progresses to the failed stage when
        download fails with an exception.
        """
        downloader = make_fail_downloader(OSError("Something is wrong"))
        recoverer = StatefulRecoverer()
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            first = Deferred.fromCoroutine(recoverer.recover(downloader, cursor))
            self.assertThat(
                first,
                succeeded(Always()),
            )
            self.assertThat(
                recoverer.state(),
                MatchesStructure(
                    stage=Equals(RecoveryStages.download_failed),
                ),
            )

    def test_failed_after_recover_failed(self):
        """
        ``StatefulRecoverer`` automatically progresses to the failed stage when
        recovery fails with an exception.
        """
        downloader = make_canned_downloader(b"non-sql junk to provoke a failure")
        recoverer = StatefulRecoverer()
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            first = Deferred.fromCoroutine(recoverer.recover(downloader, cursor))
            self.assertThat(
                first,
                succeeded(Always()),
            )
            self.assertThat(
                recoverer.state(),
                MatchesStructure(
                    stage=Equals(RecoveryStages.import_failed),
                ),
            )

    def test_cannot_recover_twice(self):
        """
        A second call to ``StatefulRecoverer.recover`` fails with
        ``AlreadyRecovering``.
        """
        downloader = noop_downloader
        recoverer = StatefulRecoverer()
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            self.assertThat(
                Deferred.fromCoroutine(recoverer.recover(downloader, cursor)),
                succeeded(Always()),
            )
            second = Deferred.fromCoroutine(recoverer.recover(downloader, cursor))
            self.assertThat(
                second,
                failed(
                    AfterPreprocessing(
                        lambda f: f.value,
                        IsInstance(AlreadyRecovering),
                    ),
                ),
            )


class TahoeLAFSDownloaderTests(TestCase):
    """
    Tests for ``get_tahoe_lafs_downloader`` and ``tahoe_lafs_downloader``.
    """

    # Support test methods that return a Deferred.
    run_tests_with = AsynchronousDeferredRunTest.make_factory(timeout=60.0)

    # Get a Tahoe-LAFS client node connected to a storage node.
    resources = [("client", client_manager)]

    def setUp(self):
        super().setUp()
        setUpResources(self, self.resources, None)
        self.addCleanup(lambda: tearDownResources(self, self.resources, None))

    @inlineCallbacks
    def test_get_downloader(self):
        """
        ``get_tahoe_lafs_downloader`` returns a downloader factory that can be
        used to download objects using a Tahoe-LAFS client.
        """
        snapshot_path = FilePath(self.useFixture(TempDir()).join("snapshot-source"))
        snapshot_path.setContent(b"snapshot data")

        config = read_config(self.client.node_dir.path, "tub.port")
        # AsynchronousDeferredRunTest sets reactor on us.
        httpclient = self.useFixture(Treq(self.reactor, case=self)).client()

        replica_dir_cap_str = yield Deferred.fromCoroutine(
            make_directory(httpclient, self.client.node_url),
        )
        snapshot_cap_str = yield Deferred.fromCoroutine(
            upload(httpclient, snapshot_path, self.client.node_url)
        )
        yield Deferred.fromCoroutine(
            link(
                httpclient,
                self.client.node_url,
                replica_dir_cap_str,
                "snapshot.sql",
                snapshot_cap_str,
            )
        )

        tahoeclient = Tahoe(httpclient, config)
        get_downloader = get_tahoe_lafs_downloader(tahoeclient)
        download = get_downloader(replica_dir_cap_str)

        downloaded_snapshot_path = yield Deferred.fromCoroutine(
            download(lambda state: None)
        )
        self.assertThat(
            downloaded_snapshot_path.getContent(),
            Equals(snapshot_path.getContent()),
        )


class SetupTahoeLAFSReplicationTests(TestCase):
    """
    Tests for ``setup_tahoe_lafs_replication``.
    """

    @given(
        tahoe_configs(),
        api_auth_tokens(),
    )
    def test_already_setup(self, get_config, api_auth_token):
        """
        If replication is already set up, ``setup_tahoe_lafs_replication`` signals
        failure with ``ReplicationAlreadySetup``.
        """
        grid = MemoryGrid()
        client = grid.client()
        client.get_private_path(REPLICA_RWCAP_BASENAME).setContent(b"URI:DIR2:stuff")
        self.assertThat(
            Deferred.fromCoroutine(setup_tahoe_lafs_replication(client)),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    IsInstance(ReplicationAlreadySetup),
                ),
            ),
        )

    @given(
        tahoe_configs(),
        api_auth_tokens(),
    )
    def test_setup(self, get_config, api_auth_token):
        """
        If replication was not previously set up then
        ``setup_tahoe_lafs_replication`` signals success with a read-only
        directory capability string that it has just created and written to
        the node private directory.
        """
        grid = MemoryGrid()
        client = grid.client()

        ro_cap = run(setup_tahoe_lafs_replication(client))
        self.assertThat(ro_cap, matches_capability(Equals("DIR2-RO")))

        # Memory grid lets us download directory cap as a dict.  Kind of bogus
        # but use it for now.
        self.assertThat(
            grid.download(ro_cap),
            Equals({}),
        )

        # Peek inside the node private state to make sure the capability was
        # written.
        self.assertThat(
            client.get_private_path(REPLICA_RWCAP_BASENAME).getContent(),
            AfterPreprocessing(
                attenuate_writecap,
                Equals(ro_cap),
            ),
        )
