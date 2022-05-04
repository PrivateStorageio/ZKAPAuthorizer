"""
Tests for ``_zkapauthorizer.recover``, the replication recovery system.
"""

from io import BytesIO
from sqlite3 import connect

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
from testtools.matchers import (
    AfterPreprocessing,
    Always,
    Equals,
    Is,
    IsInstance,
    MatchesStructure,
)
from testtools.twistedsupport import failed, has_no_result, succeeded
from twisted.internet.defer import Deferred, inlineCallbacks
from zope.interface import Interface

from ..config import REPLICA_RWCAP_BASENAME
from ..recover import (
    RecoveryStages,
    StatefulRecoverer,
    get_tahoe_lafs_downloader,
    make_canned_downloader,
    make_fail_downloader,
    noop_downloader,
    recover,
    statements_from_snapshot,
)
from ..replicate import (
    AlreadySettingUp,
    ReplicationAlreadySetup,
    get_tahoe_lafs_direntry_uploader,
    setup_tahoe_lafs_replication,
    snapshot,
    statements_to_snapshot,
)
from ..sql import Table, create_table
from ..tahoe import ITahoeClient, MemoryGrid, attenuate_writecap
from .common import delayedProxy
from .matchers import equals_database, matches_capability, raises
from .strategies import (
    deletes,
    inserts,
    sql_identifiers,
    tables,
    tahoe_configs,
    updates,
)


class SnapshotEncodingTests(TestCase):
    """
    Tests for a snapshot's round-trip through encoding and decoding.
    """

    @given(lists(text()))
    def test_roundtrip(self, statements):
        """
        Statements of a snapshot can be encoded to bytes and decoded to the same
        statements again using ``statements_to_snapshot`` and
        ``statements_from_snapshot``.
        """
        loaded = list(
            statements_from_snapshot(
                BytesIO(b"".join(statements_to_snapshot(statements)))
            )
        )
        self.assertThat(
            # They are allowed to differ by leading and trailing whitespace
            # because such whitespace is meaningless in a SQL statement.
            [s.strip() for s in statements],
            Equals(loaded),
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
        self.tables: dict[str, Table] = {}

    @invariant()
    def snapshot_equals_database(self):
        """
        At all points a snapshot of the database can be used to construct a new
        database with the same contents.
        """
        snapshot_bytes = snapshot(self.connection)
        new = connect(":memory:")
        cursor = new.cursor()
        with new:
            recover(BytesIO(snapshot_bytes), cursor)
        self.case.assertThat(
            new,
            equals_database(reference=self.connection),
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


class RecoverTests(TestCase):
    """
    Tests for ``recover``.
    """

    def test_stateful(self):
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
        snapshot = b"".join(
            statements_to_snapshot(
                [
                    "CREATE TABLE [succeeded] ( [a] TEXT );\n",
                    "INSERT INTO [succeeded] ([a]) VALUES ('yes');\n",
                ]
            )
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
        A second call to ``StatefulRecoverer.recover`` returns ``None`` without
        altering the recovery state.
        """
        downloader = noop_downloader
        recoverer = StatefulRecoverer()
        with connect(":memory:") as conn:
            cursor = conn.cursor()
            self.assertThat(
                Deferred.fromCoroutine(recoverer.recover(downloader, cursor)),
                succeeded(Always()),
            )
            stage = recoverer.state().stage
            second = Deferred.fromCoroutine(recoverer.recover(downloader, cursor))
            self.assertThat(
                second,
                succeeded(Is(None)),
            )
            self.assertThat(recoverer.state().stage, Equals(stage))


class TahoeLAFSDownloaderTests(TestCase):
    """
    Tests for ``get_tahoe_lafs_downloader`` and ``tahoe_lafs_downloader``.
    """

    @inlineCallbacks
    def test_uploader_and_downloader(self):
        """
        ``get_tahoe_lafs_downloader`` returns a downloader factory that can be
        used to download objects using a Tahoe-LAFS client.
        """
        grid = MemoryGrid()
        tahoeclient = grid.client()
        replica_dir_cap_str = grid.make_directory()

        # use the uploader to push some replica data
        upload = get_tahoe_lafs_direntry_uploader(
            tahoeclient,
            replica_dir_cap_str,
        )
        expected = b"snapshot data"
        yield Deferred.fromCoroutine(upload("snapshot.sql", lambda: BytesIO(expected)))

        # download it with the downloader
        get_downloader = get_tahoe_lafs_downloader(tahoeclient)
        download = get_downloader(replica_dir_cap_str)

        downloaded_snapshot_path = yield Deferred.fromCoroutine(
            download(lambda state: None)
        )
        self.assertThat(
            downloaded_snapshot_path.getContent(),
            Equals(expected),
        )


class SetupTahoeLAFSReplicationTests(TestCase):
    """
    Tests for ``setup_tahoe_lafs_replication``.
    """

    @given(
        tahoe_configs(),
    )
    def test_already_setup(self, get_config):
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
    )
    def test_already_setting_up(self, get_config):
        """
        If ``setup_tahoe_lafs_replication`` is called a second time before a first
        call has finished then the second call fails with
        ``AlreadySettingUp``.
        """
        grid = MemoryGrid()
        controller, client = delayedProxy(ITahoeClient, grid.client())
        first = Deferred.fromCoroutine(setup_tahoe_lafs_replication(client))
        second = Deferred.fromCoroutine(setup_tahoe_lafs_replication(client))

        controller.run()
        self.assertThat(first, succeeded(Always()))
        self.assertThat(
            second,
            failed(AfterPreprocessing(lambda f: f.type, Equals(AlreadySettingUp))),
        )

    @given(
        tahoe_configs(),
    )
    def test_setup(self, get_config):
        """
        If replication was not previously set up then
        ``setup_tahoe_lafs_replication`` signals success with a read-only
        directory capability string that it has just created and written to
        the node private directory.
        """
        grid = MemoryGrid()
        client = grid.client()

        results = []
        d = Deferred.fromCoroutine(setup_tahoe_lafs_replication(client))
        d.addCallback(lambda x: results.append(x) or x)
        self.assertThat(
            d,
            succeeded(matches_capability(Equals("DIR2-RO"))),
        )
        ro_cap = results[0]

        self.assertThat(
            Deferred.fromCoroutine(client.list_directory(ro_cap)),
            succeeded(Equals({})),
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


class IFoo(Interface):
    async def bar(a):
        pass

    def baz(a):
        pass


class Foo:
    async def bar(self, a):
        return (self, a)

    def baz(self, a):
        return [self, a]


class DelayedTests(TestCase):
    """
    Tests for ``delayedProxy``.
    """

    def test_asynchronous(self):
        """
        A coroutine function on the proxied object can have its execution
        arbitrarily delayed using the controller.
        """
        original = Foo()
        controller, delayed = delayedProxy(IFoo, original)
        d = Deferred.fromCoroutine(delayed.bar(10))
        self.assertThat(d, has_no_result())
        controller.run()
        self.assertThat(d, succeeded(Equals((original, 10))))

    def test_synchronous(self):
        """
        A regular function on the proxied object is executed as normal with no
        delay.
        """
        original = Foo()
        controller, delayed = delayedProxy(IFoo, original)
        self.assertThat(delayed.baz(5), Equals([original, 5]))

    def test_nothing_waiting(self):
        """
        If nothing is waiting then ``controller.run`` raises ``ValueError``.
        """
        controller, delayed = delayedProxy(IFoo, Foo())
        self.assertThat(
            lambda: controller.run(),
            raises(ValueError),
        )
