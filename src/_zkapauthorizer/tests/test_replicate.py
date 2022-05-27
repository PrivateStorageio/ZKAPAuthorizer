"""
Tests for the replication system in ``_zkapauthorizer.replicate``.
"""

from base64 import b64encode, urlsafe_b64encode
from functools import partial
from io import BytesIO
from os import urandom
from sqlite3 import OperationalError, ProgrammingError, connect
from typing import Callable, Optional

from attrs import frozen
from eliot import log_call, start_action
from hypothesis import given
from hypothesis.strategies import lists, text
from testtools import TestCase
from testtools.matchers import (
    AfterPreprocessing,
    Contains,
    Equals,
    HasLength,
    MatchesAll,
    MatchesDict,
    MatchesStructure,
    Mismatch,
    Not,
    raises,
)
from testtools.matchers._higherorder import MismatchesAll
from testtools.twistedsupport import succeeded
from twisted.internet.defer import Deferred
from twisted.python.filepath import FilePath

from ..config import REPLICA_RWCAP_BASENAME
from ..model import RandomToken, VoucherStore, aware_now
from ..replicate import (
    EventStream,
    Replica,
    get_events,
    get_tahoe_lafs_direntry_lister,
    get_tahoe_lafs_direntry_pruner,
    get_tahoe_lafs_direntry_replica,
    replication_service,
    with_replication,
)
from ..spending import SpendingController
from ..sql import Cursor
from ..tahoe import CapStr, DataProvider, DirectoryEntry, ITahoeClient, MemoryGrid
from .common import delayedProxy, from_awaitable
from .fixtures import TempDir, TemporaryVoucherStore
from .matchers import Always, Matcher, returns

# Helper to construct the replication wrapper without immediately enabling
# replication.
with_postponed_replication = partial(with_replication, enable_replication=False)


@frozen
class CountBasedPolicy:
    """
    A snapshot policy that is based only on the number of files in the
    replica.

    :ivar replica_file_limit: The maximum number of files which will be
        allowed to exist in the replica before a snapshot is indicated.
    """

    replica_file_limit: int

    def should_snapshot(self, snapshot_size: int, replica_sizes: list[int]) -> bool:
        return len(replica_sizes) >= self.replica_file_limit


naive_policy = CountBasedPolicy(replica_file_limit=1000)


class ReplicationConnectionTests(TestCase):
    """
    Tests for the SQLite3 connection-like object returned by
    ``with_replication``.
    """

    def test_close(self) -> None:
        """
        The connection object and its cursors can be closed.
        """
        conn = with_postponed_replication(connect(":memory:"))
        cursor = conn.cursor()
        cursor.close()
        self.assertThat(
            lambda: cursor.execute("SELECT 1", ()),
            raises(ProgrammingError),
        )
        conn.close()
        expected = ProgrammingError
        try:
            with conn:
                pass
        except expected:
            pass
        except BaseException as e:
            self.fail(f"using connection after close, {e} raised instead of {expected}")
        else:
            self.fail(
                f"using connection after close, nothing raised instead of {expected}"
            )

    def test_context_manager_success(self) -> None:
        """
        The connection object is a context manager that commits the transaction
        when the managed block completes normally.
        """
        dbpath = self.useFixture(TempDir()).join("db.sqlite")
        conn = with_postponed_replication(connect(dbpath))
        with conn:
            cursor: Cursor = conn.cursor()
            cursor.execute("BEGIN", ())
            cursor.execute('CREATE TABLE "foo" ("a" INT)', ())
            cursor.execute('INSERT INTO "foo" VALUES (?)', (42,))

        db = connect(dbpath)
        cursor = db.cursor()
        cursor.execute('SELECT "a" FROM foo', ())
        self.assertThat(
            cursor.fetchall(),
            Equals([(42,)]),
        )

    def test_context_manager_exception(self) -> None:
        """
        The connection object is a context manager that rolls the transaction back
        when the managed block raises an exception.
        """

        class ApplicationError(Exception):
            pass

        dbpath = self.useFixture(TempDir()).join("db.sqlite")
        conn = with_postponed_replication(connect(dbpath))
        try:
            with conn:
                cursor: Cursor = conn.cursor()
                cursor.execute("BEGIN", ())
                cursor.execute('CREATE TABLE "foo" ("a" INT)', ())
                cursor.execute('INSERT INTO "foo" VALUES (?)', (42,))
                raise ApplicationError()
        except ApplicationError:
            pass
        else:
            self.fail("expected exception to propagate through context manager")

        db = connect(dbpath)
        cursor = db.cursor()

        # The table won't even exist.
        self.assertThat(
            lambda: cursor.execute('SELECT "a" FROM foo', ()),
            raises(OperationalError),
        )

    def test_important_exception(self) -> None:
        """
        An exception inside an `important()` context-manager is allowed to
        propagate
        """
        conn = with_postponed_replication(connect(":memory:"))
        imp = conn.cursor().important()

        class ApplicationError(Exception):
            pass

        try:
            with imp:
                raise ApplicationError()
        except ApplicationError:
            pass
        else:
            self.fail("exception should propagate")

    def test_importance_ends(self) -> None:
        """
        After the `important()` context-manager is exited, the cursor is no longer
        marked as important.
        """
        mutations = []
        conn = with_replication(connect(":memory:"), True)
        conn.add_mutation_observer(
            lambda cursor, observed: lambda: mutations.append(observed)
        )
        important_statement = "CREATE TABLE 'important' ( 'a' INT )"
        less_important_statement = "CREATE TABLE 'less_important' ( 'a' INT )"
        with conn:
            cursor = conn.cursor()
            with cursor.important():
                cursor.execute(important_statement, ())
            cursor.execute(less_important_statement, ())

        self.assertThat(
            mutations,
            Equals(
                [
                    [
                        (True, important_statement, ((),)),
                        (False, less_important_statement, ((),)),
                    ]
                ]
            ),
        )

    def test_executemany(self) -> None:
        """
        The connection's cursor objects have an ``executemany`` method that
        operates in the usual way.
        """
        conn = with_postponed_replication(connect(":memory:"))
        cursor = conn.cursor()
        cursor.execute("BEGIN", ())
        cursor.execute('CREATE TABLE "foo" ("a" INT)', ())
        cursor.execute('INSERT INTO "foo" VALUES (?)', (1,))
        cursor.executemany('INSERT INTO "foo" VALUES (?)', [(3,), (5,), (7,)])

        # execute is supposed to update lastrowid but executemany is not
        # supposed to
        self.assertThat(
            cursor.lastrowid,
            Equals(1),
        )
        self.assertThat(
            cursor.rowcount,
            Equals(3),
        )
        cursor.execute('SELECT * FROM "foo"', ())
        self.assertThat(
            cursor.fetchall(),
            Equals([(1,), (3,), (5,), (7,)]),
        )

        cursor.execute('SELECT * FROM "foo"', ())
        for expected in [1, 3, 5, 7]:
            self.assertThat(
                cursor.fetchone(),
                Equals((expected,)),
            )
        self.assertThat(
            cursor.fetchone(),
            Equals(None),
        )

    def test_fetchmany(self) -> None:
        """
        The connection's cursor objects have a ``fetchmany`` method that operates
        in the usual way.
        """
        conn = with_postponed_replication(connect(":memory:"))
        cursor = conn.cursor()
        cursor.execute("BEGIN", ())
        cursor.execute('CREATE TABLE "foo" ("a" INT)', ())
        cursor.executemany('INSERT INTO "foo" VALUES (?)', [(3,), (5,), (7,)])

        cursor.execute('SELECT "a" FROM "foo"', ())
        self.assertThat(
            cursor.fetchmany(2),
            Equals([(3,), (5,)]),
        )
        self.assertThat(
            cursor.fetchmany(2),
            Equals([(7,)]),
        )
        self.assertThat(
            cursor.fetchmany(2),
            Equals([]),
        )


def match_upload(
    name_matcher: Matcher[str],
    stream_matcher: Matcher[EventStream],
) -> Matcher[tuple[str, EventStream]]:
    """
    Match faked Tahoe-LAFS EventStream uploads with matching name and
    EventStream.
    """
    return _MatchUpload(name_matcher, stream_matcher)


@frozen
class _MatchUpload(Matcher):
    """
    Match a two-tuple where the first element is the name of an upload and the
    second element is a function that returns a ``BinaryIO`` that has contents
    that can be parsed as an ``EventStream``.

    :ivar name_matcher: A matcher for the upload name.

    :ivar stream_matcher: A matcher for the ``EventStream`` that can be
        deserialized from the bytes of the upload.
    """

    name_matcher: Matcher[str]
    stream_matcher: Matcher[EventStream]

    def match(self, matchee: tuple[str, DataProvider]) -> Optional[Mismatch]:
        """
        Do the matching.
        """
        name, get_data = matchee

        maybe_mismatches: list[Optional[Mismatch]] = []
        maybe_mismatches.append(self.name_matcher.match(name))
        try:
            stream = EventStream.from_bytes(get_data())
        except Exception as e:
            maybe_mismatches.append(Mismatch(f"Parsing the stream failed: {e}"))
        else:
            maybe_mismatches.append(self.stream_matcher.match(stream))

        mismatches = [m for m in maybe_mismatches if m is not None]
        if len(mismatches) > 0:
            return MismatchesAll(mismatches)
        return None


async def noop_upload(name, get_bytes) -> None:
    pass


async def noop_prune(predicate) -> None:
    pass


async def noop_list_entries() -> dict[str, DirectoryEntry]:
    return {}


# A replica that actually does nothing.  Used by tests that don't interact
# with this part of the replication system but still need a value of the right
# type.
noop_replica = Replica(noop_upload, noop_prune, noop_list_entries)


def has_files(grid: MemoryGrid, dir_cap: CapStr, count: int) -> bool:
    """
    A predicate that returns True only when the directory indicated has at
    least the given number of children in it.
    """
    return len(grid.list_directory(dir_cap)) >= count


def repeat_until(condition: Callable[[], bool], action: Callable[[], object]) -> None:
    """
    Run an action repeatedly until a condition is true.
    """
    while True:
        action()
        if condition():
            break


def is_event_stream(grid: MemoryGrid, **kwargs: Matcher) -> Matcher[tuple[str, dict]]:
    """
    Match a Tahoe-LAFS directory entry representing a file which can be
    retrieved from the given grid and which contains an ``EventStream`` with a
    structure matched by the given keyword arguments.
    """

    def is_filenode():
        return AfterPreprocessing(lambda item: item[0], Equals("filenode"))

    def download_event_stream(cap):
        return EventStream.from_bytes(BytesIO(grid.download(cap)))

    return MatchesAll(
        is_filenode(),
        AfterPreprocessing(
            lambda item: download_event_stream(item[1]["ro_uri"]),
            MatchesStructure(**kwargs),
        ),
    )


@log_call(action_type="zkapauthorizer:tests:add-tokens")
def add_tokens(store: VoucherStore) -> None:
    """
    Add a token to the given store.
    """
    tokens = [RandomToken(b64encode(urandom(96)))]
    voucher = urlsafe_b64encode(urandom(32))
    store.add(voucher, len(tokens), 1, lambda: tokens)


class ReplicationServiceTests(TestCase):
    """
    Tests for ``_ReplicationService``.
    """

    def test_enable_replication_on_connection(self) -> None:
        """
        When the service starts it enables replication on its database connection.
        """
        tvs = self.useFixture(TemporaryVoucherStore(aware_now))
        store = tvs.store

        # We'll spy on "events" which are only captured when the connection is
        # in replication mode.  To start, make sure that database changes are
        # not already being captured.  They should not be since nothing has
        # placed the connection into replication mode yet.
        store.start_lease_maintenance().finish()
        self.assertThat(get_events(store._connection).changes, HasLength(0))

        service = replication_service(store._connection, noop_replica, naive_policy)
        service.startService()
        self.addCleanup(service.stopService)

        # Now that replication has been enabled.  Some events should now be
        # captured.
        store.start_lease_maintenance().finish()
        self.assertThat(get_events(store._connection).changes, Not(HasLength(0)))

    def test_first_snapshot(self) -> None:
        """
        A snapshot is uploaded if there is no snapshot in the replica directory
        already.
        """
        tvs = self.useFixture(TemporaryVoucherStore(aware_now))
        store = tvs.store

        grid = MemoryGrid()
        replica_dircap = grid.make_directory()
        client = grid.client()

        replica = get_tahoe_lafs_direntry_replica(client, replica_dircap)
        service = replication_service(store._connection, replica, naive_policy)
        service.startService()
        self.addCleanup(service.stopService)

        self.assertThat(
            grid.list_directory(replica_dircap),
            Contains("snapshot"),
        )

    def test_lingering_event_stream(self) -> None:
        """
        If there are changes recorded in the local event stream that should be
        uploaded then they are uploaded soon after the replication service
        starts even if no further local changes are made.
        """
        # The starting state that we want is:
        #   (1) Replication is enabled
        #   (2) A snapshot has been uploaded
        #   (3) There is no replication service
        #   (4) There are extra changes in the event-stream
        #
        # Then we can create the replication service and watch it react to the
        # extra event-stream changes.
        #
        # To get to this state, we'll make a store and let it upload a
        # snapshot.  Then we'll stop its service, make some changes, and make
        # and start a new replication service for the new store.
        tvs = self.useFixture(TemporaryVoucherStore(aware_now))
        store = tvs.store

        grid = MemoryGrid()
        replica_dircap = grid.make_directory()
        client = grid.client()

        replica = get_tahoe_lafs_direntry_replica(client, replica_dircap)
        # This accomplishes (1).
        service = replication_service(store._connection, replica, naive_policy)
        service.startService()

        # Demonstrate (2).
        self.assertThat(
            set(grid.list_directory(replica_dircap)),
            Equals({"snapshot"}),
        )

        # Accomplish (3).
        self.assertThat(service.stopService(), succeeded(Always()))

        # Introduce some "important" changes to accomplish (4).
        add_tokens(store)

        # Verify the important changes are still in the local database and
        # have not been uploaded to the replica.
        self.assertThat(
            get_events(store._connection).changes,
            Not(HasLength(0)),
        )
        self.assertThat(
            set(grid.list_directory(replica_dircap)),
            Equals({"snapshot"}),
        )

        # Now create and start the new replication service, expecting it will
        # upload the changes in the local event stream.
        service = replication_service(store._connection, replica, naive_policy)
        service.startService()

        self.assertThat(
            get_events(store._connection).changes,
            HasLength(0),
        )
        self.assertThat(
            set(grid.list_directory(replica_dircap)),
            Equals({"snapshot", "event-stream-2"}),
        )

    def test_replicate(self) -> None:
        """
        Making changes to the voucher store while replication is turned on
        causes event-stream objects to be uploaded.
        """
        tvs = self.useFixture(TemporaryVoucherStore(aware_now))

        grid = MemoryGrid()
        replica_cap = grid.make_directory()
        rwcap_file = FilePath(tvs.config.get_private_path(REPLICA_RWCAP_BASENAME))
        rwcap_file.parent().makedirs()
        rwcap_file.setContent(replica_cap.encode("ascii"))

        # Predicate to check if the replica directory has at least some number
        # of files in it.
        has_files_bound = partial(has_files, grid, replica_cap)

        # we use this to contol when the first upload happens, so that we
        # actually use the queue
        delay_controller, delay_client = delayedProxy(
            ITahoeClient,
            grid.client(tvs.config._basedir),
        )

        srv = replication_service(
            tvs.store._connection,
            get_tahoe_lafs_direntry_replica(delay_client, replica_cap),
            naive_policy,
        )

        # run the service and produce some fake voucher etc changes
        # that cause "events" to be issued into the database
        srv.startService()
        self.addCleanup(srv.stopService)

        with start_action(action_type="zkapauthorizer:tests:wait-for-snapshot"):
            repeat_until(partial(has_files_bound, 1), delay_controller.run)

        # then it does a list_directory for pruning purposes.  if we don't let
        # it run then the event-stream upload for the first add_tokens() can't
        # start and the subsequent add_tokens calls have their data merged
        # into an upload with the first.
        with start_action(action_type="zkapauthorizer:tests:run-list-directory"):
            delay_controller.run()

        # Add some tokens, which are considered important.
        add_tokens(tvs.store)

        # Still, no uploads can complete until we let them.  Verify that's
        # working as intended by asserting there are no event streams on the
        # grid.
        self.assertThat(
            sorted(grid.list_directory(replica_cap)),
            Equals(["snapshot"]),
        )

        # Add two more groups of tokens.  These are also important.  They
        # should be included in an upload but they cannot be included in the
        # upload that already started.
        add_tokens(tvs.store)
        add_tokens(tvs.store)

        # Finish the first event-stream upload.
        with start_action(action_type="zkapauthorizer:tests:wait-for-event-stream"):
            repeat_until(partial(has_files_bound, 2), delay_controller.run)

        self.assertThat(
            sorted(grid.list_directory(replica_cap)),
            Equals(sorted(["snapshot", "event-stream-2"])),
        )

        # Allow subsequent uploads.
        with start_action(action_type="zkapauthorizer:tests:wait-for-event-stream"):
            repeat_until(partial(has_files_bound, 3), delay_controller.run)

        # Now both the first upload and a second upload should have completed.
        # There is no third upload because the data for the 2nd and 3rd
        # add_tokens calls should have been combined into a single upload.
        self.assertThat(
            grid.list_directory(replica_cap),
            MatchesDict(
                {
                    "snapshot": Always(),
                    "event-stream-2": is_event_stream(
                        grid,
                        changes=HasLength(2),
                        highest_sequence=returns(Equals(2)),
                    ),
                    "event-stream-6": is_event_stream(
                        grid,
                        changes=HasLength(4),
                        highest_sequence=returns(Equals(6)),
                    ),
                }
            ),
        )

        # since we've uploaded everything, there should be no
        # events in the store
        self.assertEqual(tuple(), get_events(tvs.store._connection).changes)

    def test_snapshot_prune(self) -> None:
        """
        Uploading a snapshot prunes irrelevant event-stream instances from
        the replica
        """
        tvs = self.useFixture(TemporaryVoucherStore(aware_now))

        grid = MemoryGrid()
        replica_cap = grid.make_directory()
        rwcap_file = FilePath(tvs.config.get_private_path(REPLICA_RWCAP_BASENAME))
        rwcap_file.parent().makedirs()
        rwcap_file.setContent(replica_cap.encode("ascii"))

        # Predicate to check if the replica directory has at least some number
        # of files in it.
        has_files_bound = partial(has_files, grid, replica_cap)

        # we use this to contol when the first upload happens, so that we
        # actually use the queue
        delay_controller, delay_client = delayedProxy(
            ITahoeClient,
            grid.client(tvs.config._basedir),
        )

        srv = replication_service(
            tvs.store._connection,
            get_tahoe_lafs_direntry_replica(delay_client, replica_cap),
            naive_policy,
        )

        # run the service and produce some fake voucher etc changes
        # that cause "events" to be issued into the database
        srv.startService()
        self.addCleanup(srv.stopService)

        with start_action(action_type="zkapauthorizer:tests:wait-for-snapshot"):
            repeat_until(partial(has_files_bound, 1), delay_controller.run)

        # then it does a list_directory for pruning purposes.  if we don't let
        # it run then the event-stream upload for the first add_tokens() can't
        # start and the subsequent add_tokens calls have their data merged
        # into an upload with the first.
        with start_action(action_type="zkapauthorizer:tests:run-list-directory"):
            delay_controller.run()

        # Add some tokens, which are considered important.
        voucher0 = urlsafe_b64encode(urandom(32))
        tvs.redeem(voucher0, 20)

        # Allow the resulting event-stream upload to complete.
        with start_action(action_type="zkapauthorizer:tests:wait-for-event-stream"):
            repeat_until(partial(has_files_bound, 2), delay_controller.run)

        # ..so we should have uploaded here
        self.assertThat(
            grid.list_directory(replica_cap),
            MatchesDict(
                {
                    "snapshot": Always(),
                    "event-stream-21": is_event_stream(
                        grid,
                        changes=HasLength(21),
                        highest_sequence=returns(Equals(21)),
                    ),
                }
            ),
        )

        # do some work that isn't deemed "important"
        pass_factory = SpendingController.for_store(
            tokens_to_passes=tvs.redeemer.tokens_to_passes,
            store=tvs.store,
        )
        pass_factory.get(b"message0", 10)

        self.assertNotEqual(tuple(), get_events(tvs.store._connection).changes)

        # we should _not_ have uploaded the above changes yet (because
        # they aren't "important") and so they should still exist in
        # the store
        self.assertNotEqual(tuple(), get_events(tvs.store._connection).changes)

        # trigger a snapshot upload
        srv.queue_snapshot_upload()  # type: ignore

        # Let the snapshot upload and pruning processes run.
        delay_controller.run()
        delay_controller.run()
        delay_controller.run()
        delay_controller.run()
        delay_controller.run()

        # now there should be no local changes
        self.assertEqual(tuple(), get_events(tvs.store._connection).changes)
        # ...and we should have pruned the prior event-stream .. so we
        # interrogate the predicate we _were_ given to ensure it would
        # have said "yes" to the event-stream we did upload

        self.assertThat(
            grid.list_directory(replica_cap),
            MatchesDict(
                {
                    "snapshot": Always(),
                }
            ),
        )

    def test_snapshot_again(self):
        """
        A new snapshot is uploaded and existing event streams are pruned if the
        cost to maintain the current replica snapshot and event streams is
        more than X times the cost to store a new snapshot of the database.
        """
        # The starting state that we want is:
        #    (1) Replication is enabled
        #    (2) A snapshot has been uploaded
        #    (3) An event stream has been uploaded
        #
        # Then we can have the snapshot policy decide it is time to upload a
        # snapshot and observe the consequences.
        tvs = self.useFixture(TemporaryVoucherStore(aware_now))
        store = tvs.store

        grid = MemoryGrid()
        replica_dircap = grid.make_directory()
        client = grid.client()

        # This policy will decide it is time to upload after 1 snapshot + 2
        # event streams are uploaded.
        snapshot_policy = CountBasedPolicy(replica_file_limit=3)

        replica = get_tahoe_lafs_direntry_replica(client, replica_dircap)
        # This accomplishes (1).
        service = replication_service(store._connection, replica, snapshot_policy)
        service.startService()

        # Demonstrate (2).
        self.assertThat(
            set(grid.list_directory(replica_dircap)),
            Equals({"snapshot"}),
        )

        # Make an important change to get to (3).
        add_tokens(store)
        self.assertThat(
            set(grid.list_directory(replica_dircap)),
            Equals({"snapshot", "event-stream-2"}),
        )

        # Make another important change to push us over the limit.
        add_tokens(store)

        # The event streams should have been pruned and the new snapshot
        # uploaded.
        self.assertThat(
            set(grid.list_directory(replica_dircap)),
            Equals({"snapshot"}),
        )


class TahoeDirectoryListerTests(TestCase):
    """
    Tests for ``get_tahoe_lafs_direntry_lister``.
    """

    @given(
        directory_names=lists(text(max_size=100), max_size=3, unique=True),
        file_names=lists(text(max_size=100), max_size=3, unique=True),
    )
    def test_list(self, directory_names, file_names) -> None:
        """
        ``get_tahoe_lafs_direntry_lister`` returns a callable that can read the
        entries details from a Tahoe-LAFS directory.
        """
        filedata = b"somedata"
        grid = MemoryGrid()
        dircap = grid.make_directory()
        for name in directory_names:
            grid.link(dircap, name, grid.make_directory())
        for name in file_names:
            grid.link(dircap, name, grid.upload(filedata))

        client = grid.client()
        lister = get_tahoe_lafs_direntry_lister(client, dircap)

        expected = {name: DirectoryEntry("dirnode", 0) for name in directory_names}
        expected.update(
            {name: DirectoryEntry("filenode", len(filedata)) for name in file_names}
        )

        self.assertThat(
            from_awaitable(lister()),
            succeeded(Equals(expected)),
        )


class TahoeDirectoryPrunerTests(TestCase):
    """
    Tests for `get_tahoe_lafs_direntry_pruner`
    """

    def test_prune(self) -> None:
        """
        ``get_tahoe_lafs_direntry_pruner`` returns a function that unlinks entries
        from a Tahoe-LAFS mutable directory.
        """
        ignore = ["one", "two"]
        delete = ["three", "four"]

        grid = MemoryGrid()
        dircap = grid.make_directory()
        for name in ignore + delete:
            filecap = grid.upload(b"some data")
            grid.link(dircap, name, filecap)

        client = grid.client()
        pruner = get_tahoe_lafs_direntry_pruner(client, dircap)

        # ask the pruner to delete some of the files
        self.assertThat(
            # prune(..) returns a Coroutine but it declares it as an Awaitable
            # so mypy tells us it won't work with fromCoroutine.
            Deferred.fromCoroutine(pruner(lambda fname: fname in delete)),  # type: ignore
            succeeded(Always()),
        )

        self.assertThat(
            set(grid.list_directory(dircap).keys()),
            Equals(set(ignore)),
        )
