"""
Tests for the replication system in ``_zkapauthorizer.replicate``.
"""

from base64 import b64encode, urlsafe_b64encode
from datetime import datetime
from functools import partial
from io import BytesIO
from os import urandom
from sqlite3 import OperationalError, ProgrammingError, connect
from typing import BinaryIO, Callable, Optional

from attrs import frozen
from hypothesis import given
from testtools import TestCase
from testtools.matchers import (
    Equals,
    HasLength,
    MatchesListwise,
    MatchesStructure,
    Mismatch,
    raises,
)
from testtools.matchers._higherorder import MismatchesAll
from twisted.internet.defer import Deferred
from twisted.python.filepath import FilePath

from ..config import REPLICA_RWCAP_BASENAME, EmptyConfig
from ..model import RandomToken
from ..recover import recover
from ..replicate import (
    EventStream,
    get_events,
    replication_service,
    snapshot,
    with_replication,
)
from .fixtures import TempDir, TemporaryVoucherStore
from .matchers import Matcher, equals_database, returns
from .strategies import datetimes, tahoe_configs

# Helper to construct the replication wrapper without immediately enabling
# replication.
with_postponed_replication = partial(with_replication, enable_replication=False)


class ReplicationConnectionTests(TestCase):
    """
    Tests for the SQLite3 connection-like object returned by
    ``with_replication``.
    """

    def test_close(self):
        """
        The connection object and its cursors can be closed.
        """
        conn = with_postponed_replication(connect(":memory:"))
        cursor = conn.cursor()
        cursor.close()
        self.assertThat(
            lambda: cursor.execute("SELECT 1"),
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

    def test_context_manager_success(self):
        """
        The connection object is a context manager that commits the transaction
        when the managed block completes normally.
        """
        dbpath = self.useFixture(TempDir()).join("db.sqlite")
        conn = with_postponed_replication(connect(dbpath))
        with conn:
            cursor = conn.cursor()
            cursor.execute("BEGIN")
            cursor.execute('CREATE TABLE "foo" ("a" INT)')
            cursor.execute('INSERT INTO "foo" VALUES (?)', (42,))

        db = connect(dbpath)
        cursor = db.cursor()
        cursor.execute('SELECT "a" FROM foo')
        self.assertThat(
            cursor.fetchall(),
            Equals([(42,)]),
        )

    def test_context_manager_exception(self):
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
                cursor = conn.cursor()
                cursor.execute("BEGIN")
                cursor.execute('CREATE TABLE "foo" ("a" INT)')
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
            lambda: cursor.execute('SELECT "a" FROM foo'),
            raises(OperationalError),
        )

    def test_important_exception(self):
        """
        An exception inside an `important()` context-manager is allowed to
        propagate
        """
        dbpath = self.useFixture(TempDir()).join("db.sqlite")
        conn = with_postponed_replication(connect(dbpath))
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

    def test_executemany(self):
        """
        The connection's cursor objects have an ``executemany`` method that
        operates in the usual way.
        """
        conn = with_postponed_replication(connect(":memory:"))
        cursor = conn.cursor()
        cursor.execute("BEGIN")
        cursor.execute('CREATE TABLE "foo" ("a" INT)')
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
        cursor.execute('SELECT * FROM "foo"')
        self.assertThat(
            cursor.fetchall(),
            Equals([(1,), (3,), (5,), (7,)]),
        )

        cursor.execute('SELECT * FROM "foo"')
        for expected in [1, 3, 5, 7]:
            self.assertThat(
                cursor.fetchone(),
                Equals((expected,)),
            )
        self.assertThat(
            cursor.fetchone(),
            Equals(None),
        )

    def test_fetchmany(self):
        """
        The connection's cursor objects have a ``fetchmany`` method that operates
        in the usual way.
        """
        conn = with_postponed_replication(connect(":memory:"))
        cursor = conn.cursor()
        cursor.execute("BEGIN")
        cursor.execute('CREATE TABLE "foo" ("a" INT)')
        cursor.executemany('INSERT INTO "foo" VALUES (?)', [(3,), (5,), (7,)])

        cursor.execute('SELECT "a" FROM "foo"')
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

    def test_snapshot(self):
        """
        The state of the database is available via the connection's ``snapshot``
        method.
        """
        dbpath_a = self.useFixture(TempDir()).join("db.sqlite")
        conn_a = with_postponed_replication(connect(dbpath_a))
        with conn_a:
            cursor = conn_a.cursor()
            cursor.execute('CREATE TABLE "foo" ("a" INT)', ())
            cursor.execute('INSERT INTO "foo" VALUES (?)', (1,))

        a_snapshot = snapshot(conn_a)

        dbpath_b = self.useFixture(TempDir()).join("db.sqlite")
        conn_b = with_postponed_replication(connect(dbpath_b))

        with conn_b:
            recover(BytesIO(a_snapshot), conn_b.cursor())

        self.assertThat(
            conn_a,
            equals_database(conn_b),
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

    def match(self, matchee: tuple[str, Callable[[], BinaryIO]]) -> Optional[Mismatch]:
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


class ReplicationServiceTests(TestCase):
    """
    Tests for ``_ReplicationService``.
    """

    def test_replicate(self) -> None:
        """
        Making changes to the voucher store while replication is turned on
        causes event-stream objects to be uploaded.
        """

        def get_config(rootpath, portnumfile):
            return EmptyConfig(FilePath(rootpath))

        tvs = self.useFixture(TemporaryVoucherStore(get_config, lambda: datetime.now()))

        rwcap_file = FilePath(tvs.config.get_private_path(REPLICA_RWCAP_BASENAME))
        rwcap_file.parent().makedirs()
        rwcap_file.setContent(b"URL:DIR2:stuff")

        # we use this to contol when the first upload happens, so that we
        # actually use the queue
        wait_d: Deferred[None] = Deferred()

        uploads = []
        upload_completed = False

        async def uploader(name, get_data):
            uploads.append((name, get_data))
            await wait_d
            nonlocal upload_completed
            upload_completed = True

        srv = replication_service(tvs.store._connection, uploader)

        # run the service and produce some fake voucher etc changes
        # that cause "events" to be issued into the database
        srv.startService()
        self.addCleanup(srv.stopService)

        def add_tokens():
            tokens = [RandomToken(b64encode(urandom(96))) for _ in range(10)]
            voucher = urlsafe_b64encode(urandom(32))
            tvs.store.add(voucher, len(tokens), 1, lambda: tokens)

        # Add some tokens, which are considered important.
        add_tokens()

        # Still, the upload cannot complete until we fire wait_d.  Verify
        # that's working as intended.
        self.assertFalse(upload_completed)

        # Add two more groups of tokens.  These are also important.  They
        # should be included in an upload but they cannot be included in the
        # upload that already started.
        add_tokens()
        add_tokens()

        # Finish the first upload.
        wait_d.callback(None)
        self.assertTrue(upload_completed)

        # Now both the first upload and a second upload should have completed.
        # There is no third upload because the data for the 2nd and 3rd
        # add_tokens calls should have been combined into a single upload.
        self.assertThat(
            uploads,
            MatchesListwise(
                [
                    match_upload(
                        Equals("event-stream-11"),
                        MatchesStructure(
                            changes=HasLength(11),
                            highest_sequence=returns(Equals(11)),
                        ),
                    ),
                    match_upload(
                        Equals("event-stream-33"),
                        MatchesStructure(
                            changes=HasLength(22),
                            highest_sequence=returns(Equals(33)),
                        ),
                    ),
                ],
            ),
        )

        # since we've uploaded everything, there should be no
        # events in the store
        self.assertEqual(
            tuple(), get_events(tvs.store._connection._conn.cursor()).changes
        )


class HypothesisReplicationServiceTests(TestCase):
    """
    Tests for ``_ReplicationService``.
    """

    @given(tahoe_configs(), datetimes())
    def test_enable_replication_on_connection(self, get_config, now):
        """
        When the service starts it enables replication on its database connection.
        """
        tvs = self.useFixture(TemporaryVoucherStore(get_config, lambda: now))

        async def uploader(name, get_bytes):
            pass

        service = replication_service(tvs.store._connection, uploader)
        service.startService()
        try:
            self.assertThat(tvs.store._connection._replicating, Equals(True))
        finally:
            service.stopService()
