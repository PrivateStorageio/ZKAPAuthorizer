"""
Tests for ``_zkapauthorizer.recover``, the replication recovery system.
"""

from io import BytesIO
from itertools import count
from sqlite3 import connect
from typing import TypeVar

import attrs
import cbor2
from hypothesis import assume, given, note, settings
from hypothesis.stateful import (
    RuleBasedStateMachine,
    invariant,
    precondition,
    rule,
    run_state_machine_as_test,
)
from hypothesis.strategies import (
    binary,
    builds,
    data,
    integers,
    just,
    lists,
    randoms,
    sampled_from,
    text,
)
from testtools import TestCase
from testtools.matchers import AfterPreprocessing, Always, Equals, Is, MatchesStructure
from testtools.twistedsupport import failed, has_no_result, succeeded
from twisted.internet.defer import Deferred
from zope.interface import Interface

from ..config import REPLICA_RWCAP_BASENAME
from ..recover import (
    RecoveryStages,
    Replica,
    StatefulRecoverer,
    get_tahoe_lafs_downloader,
    load_event_streams,
    make_canned_downloader,
    make_fail_downloader,
    noop_downloader,
    recover_event_stream,
    recover_snapshot,
    sorted_event_streams,
    statements_from_snapshot,
)
from ..replicate import (
    SNAPSHOT_NAME,
    AlreadySettingUp,
    Change,
    EventStream,
    ReplicationAlreadySetup,
    event_stream_name,
    get_tahoe_lafs_direntry_uploader,
    setup_tahoe_lafs_replication,
    snapshot,
    statements_to_snapshot,
)
from ..sql import Table, create_table
from ..tahoe import ITahoeClient, MemoryGrid, attenuate_writecap, capability_from_string
from .common import delayedProxy, from_awaitable
from .matchers import equals_database, matches_capability, raises
from .strategies import (
    deletes,
    inserts,
    sql_identifiers,
    tables,
    tahoe_configs,
    updates,
)

T = TypeVar("T")


class SnapshotEncodingTests(TestCase):
    """
    Tests for a snapshot's round-trip through encoding and decoding.
    """

    @given(lists(text()))
    def test_roundtrip(self, statements) -> None:
        """
        Statements of a snapshot can be encoded to bytes and decoded to the same
        statements again using ``statements_to_snapshot`` and
        ``statements_from_snapshot``.
        """
        loaded = list(
            statements_from_snapshot(
                lambda: BytesIO(statements_to_snapshot(statements))
            )
        )
        self.assertThat(
            # They are allowed to differ by leading and trailing whitespace
            # because such whitespace is meaningless in a SQL statement.
            statements,
            Equals(loaded),
        )

    def test_unknown_snapshot_version(self) -> None:
        """
        ``statements_from_snapshot`` raises ``ValueError`` when called with a
        Snapshot with an unknown version number.
        """
        self.assertThat(
            lambda: statements_from_snapshot(
                lambda: BytesIO(cbor2.dumps({"version": -1}))
            ),
            raises(ValueError),
        )


class SnapshotMachine(RuleBasedStateMachine):
    """
    Transition rules for a state machine corresponding to the state of a
    SQLite3 database.  Transitions are schema changes, row inserts, row
    updates, row deletions, etc.
    """

    def __init__(self, case) -> None:
        super().__init__()
        self.case = case
        self.connection = connect(":memory:")
        self.tables: dict[str, Table] = {}

    @invariant()
    def snapshot_equals_database(self) -> None:
        """
        At all points a snapshot of the database can be used to construct a new
        database with the same contents.
        """
        snapshot_statements = statements_from_snapshot(
            lambda: BytesIO(snapshot(self.connection))
        )
        new = connect(":memory:")
        cursor = new.cursor()
        with new:
            recover_snapshot(snapshot_statements, cursor)
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
    def create_table(self, name, table) -> None:
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
    def modify_rows(self, change_types, random, data) -> None:
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

    def test_stateful(self) -> None:
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

    def test_succeeded_after_recover(self) -> None:
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

    def test_state_recovered(self) -> None:
        """
        After ``StatefulRecoverer`` reaches the ``succeeded`` state the state
        represented by the downloaded snapshot is present in the database
        itself.
        """
        snapshot = statements_to_snapshot(
            iter(
                [
                    "CREATE TABLE [succeeded] ( [a] TEXT );\n",
                    "INSERT INTO [succeeded] ([a]) VALUES ('yes');\n",
                ]
            )
        )
        downloader = make_canned_downloader(snapshot, [])
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

    def test_failed_after_download_failed(self) -> None:
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

    def test_failed_after_recover_failed(self) -> None:
        """
        ``StatefulRecoverer`` automatically progresses to the failed stage when
        recovery fails with an exception.
        """
        downloader = make_canned_downloader(b"non-sql junk to provoke a failure", [])
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

    def test_cannot_recover_twice(self) -> None:
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


def confusing_names():
    """
    Build names as ``str`` which do not belong in a replica directory.
    """
    return text(min_size=1).filter(
        lambda name: name != SNAPSHOT_NAME and not name.startswith("event-stream-")
    )


class TahoeLAFSDownloaderTests(TestCase):
    """
    Tests for ``get_tahoe_lafs_downloader`` and ``tahoe_lafs_downloader``.
    """

    @given(
        expected_snapshot=binary(min_size=1),
        expected_event_streams=lists(binary(min_size=1)),
        confusing_directories=lists(text(min_size=1)),
        confusing_filenodes=lists(confusing_names()),
    )
    def test_uploader_and_downloader(
        self,
        expected_snapshot,
        expected_event_streams,
        confusing_directories,
        confusing_filenodes,
    ) -> None:
        """
        ``get_tahoe_lafs_downloader`` returns a downloader factory that can be
        used to download objects using a Tahoe-LAFS client.

        :param expected_snapshot: Some bytes which will serve as a serialized
            snapshot.

        :param expected_event_streams: A list of bytes, each of which will
            serve as one serialized event stream.

        :param confusing_directories: A list of names to use to link
            extraneous directories into the replica.  These should all be
            ignored.

        :param confusing_filenodes: A list of names to use to link extra files
            into the replica.  These will not overlap with the names the
            replica system actually uses in the replica directory.  These
            should all be ignored.
        """
        grid = MemoryGrid()
        tahoeclient = grid.client()
        replica_dir_cap_str = grid.make_directory()

        # use the uploader to push some replica data
        upload = get_tahoe_lafs_direntry_uploader(
            tahoeclient,
            replica_dir_cap_str,
        )
        self.assertThat(
            from_awaitable(upload(SNAPSHOT_NAME, lambda: BytesIO(expected_snapshot))),
            succeeded(Always()),
        )
        # Simulate sequence numbers for some event streams in the replica.
        sequence_counter = 0
        for event_stream_data in expected_event_streams:
            sequence_counter += len(event_stream_data)
            self.assertThat(
                from_awaitable(
                    upload(
                        event_stream_name(sequence_counter),
                        lambda: BytesIO(event_stream_data),
                    ),
                ),
                succeeded(Always()),
            )

        # Put some confusing junk in the replica.
        for entry in confusing_directories:
            grid.link(replica_dir_cap_str, entry, grid.make_directory())
        for entry in confusing_filenodes:
            grid.link(replica_dir_cap_str, entry, grid.upload(entry))

        # download it with the downloader
        get_downloader = get_tahoe_lafs_downloader(tahoeclient)
        download = get_downloader(replica_dir_cap_str)

        def read_replica_data(replica: Replica) -> tuple[bytes, list[bytes]]:
            def read(p):
                with p() as f:
                    return f.read()

            snapshot_provider, event_stream_providers = replica
            return (
                read(snapshot_provider),
                [read(e) for e in event_stream_providers],
            )

        self.assertThat(
            from_awaitable(download(lambda state: None)),
            succeeded(
                AfterPreprocessing(
                    read_replica_data,
                    Equals((expected_snapshot, expected_event_streams)),
                ),
            ),
        )


class SetupTahoeLAFSReplicationTests(TestCase):
    """
    Tests for ``setup_tahoe_lafs_replication``.
    """

    @given(
        tahoe_configs(),
    )
    def test_already_setup(self, get_config) -> None:
        """
        If replication is already set up, ``setup_tahoe_lafs_replication`` signals
        failure with ``ReplicationAlreadySetup``.
        """
        grid = MemoryGrid()
        client = grid.client()

        rwcap_bytes = grid.make_directory().encode("ascii")
        rocap_obj = capability_from_string(rwcap_bytes).get_readonly()
        rocap_bytes = rocap_obj.to_string()

        client.get_private_path(REPLICA_RWCAP_BASENAME).setContent(rwcap_bytes)

        self.assertThat(
            Deferred.fromCoroutine(setup_tahoe_lafs_replication(client)),
            failed(
                AfterPreprocessing(
                    lambda f: f.value,
                    Equals(ReplicationAlreadySetup(rocap_bytes.decode("ascii"))),
                ),
            ),
        )

    @given(
        tahoe_configs(),
    )
    def test_already_setting_up(self, get_config) -> None:
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
    def test_setup(self, get_config) -> None:
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

        def save_and_passthrough(x):
            results.append(x)
            return x

        d.addCallback(save_and_passthrough)
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
    async def bar(a) -> None:
        pass

    def baz(a) -> None:
        pass


class Foo:
    async def bar(self, a: T) -> tuple["Foo", T]:
        return (self, a)

    def baz(self, a) -> tuple[T, "Foo"]:
        return (a, self)


class DelayedTests(TestCase):
    """
    Tests for ``delayedProxy``.
    """

    def test_asynchronous(self) -> None:
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

    def test_synchronous(self) -> None:
        """
        A regular function on the proxied object is executed as normal with no
        delay.
        """
        original = Foo()
        controller, delayed = delayedProxy(IFoo, original)
        self.assertThat(delayed.baz(5), Equals((5, original)))

    def test_nothing_waiting(self) -> None:
        """
        If nothing is waiting then ``controller.run`` raises ``ValueError``.
        """
        controller, delayed = delayedProxy(IFoo, Foo())
        self.assertThat(
            lambda: controller.run(),
            raises(ValueError),
        )


class EventStreamRecoveryTests(TestCase):
    """
    Tests for functionality related to ``EventStream`` handling in the
    recovery process.
    """

    @given(
        lists(
            lists(
                builds(
                    Change,
                    sequence=integers(),
                    statement=text(),
                    arguments=just(()),
                    important=just(False),
                ),
                min_size=1,
            ),
        ),
        randoms(),
    )
    def test_by_highest_sequence(
        self, change_groups: list[list[Change]], random
    ) -> None:
        """
        ``sorted_event_streams`` returns a list of ``EventStream`` instances in
        increasing order of their ``highest_sequence`` result with empty ``EventStream`` instances excluded.
        """
        # Take the groups of Changes and build EventStreams from them,
        # renumbering the changes so they're monotonically increasing.  This
        # gives us the correct sorted order for the result without relying on
        # the sort implementation.
        seq = iter(count(1))

        def resequence(c: Change) -> Change:
            return attrs.evolve(c, sequence=next(seq))

        # Generator has incompatible item type "Change"; expected "_T_co"
        expected = [
            EventStream(
                changes=(resequence(change) for change in change_group),  # type: ignore
            )
            for change_group in change_groups
        ]

        # Create a mixed up ordering including some empty EventStreams
        shuffled = expected[:]
        shuffled.append(EventStream(changes=[]))
        random.shuffle(shuffled)

        actual = sorted_event_streams(iter(shuffled))
        self.assertThat(actual, Equals(expected))

    @given(
        lists(
            builds(
                EventStream,
                changes=lists(
                    builds(
                        Change,
                        sequence=integers(),
                        statement=text(),
                        arguments=just(()),
                        important=just(False),
                    ),
                ),
            ),
        )
    )
    def test_load_event_streams(self, expected: list[EventStream]) -> None:
        """
        ``load_event_streams`` takes an iterable of data providers and returns an
        iterator of corresponding ``EventStream`` instances.
        """
        loaded = list(load_event_streams((e.to_bytes for e in expected)))
        self.assertThat(loaded, Equals(expected))

    def test_recover_event_stream(self) -> None:
        """
        ``recover_event_stream`` applies the changes in an ``EventStream`` to a
        database.
        """
        expected = "hello, world"
        create_table = Change(1, "CREATE TABLE [foo] ([a] TEXT)", (), False)
        insert_row = Change(2, "INSERT INTO [foo] ([a]) VALUES (?)", (expected,), False)  # type: ignore

        db = connect(":memory:")
        cursor = db.cursor()
        with db:
            recover_event_stream(
                EventStream(
                    changes=iter([create_table, insert_row]),  # type: ignore
                ),
                cursor,
            )

            cursor.execute("SELECT * FROM [foo]")
            self.assertThat(
                cursor.fetchall(),
                Equals([(expected,)]),
            )
