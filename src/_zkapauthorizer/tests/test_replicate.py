"""
Tests for the replication system in ``_zkapauthorizer.replicate``.
"""

from base64 import b64encode, urlsafe_b64encode
from datetime import datetime
from functools import partial
from io import BytesIO
from os import urandom
from sqlite3 import OperationalError, ProgrammingError, connect

from allmydata.client import config_from_string
from hypothesis import given
from testtools import TestCase
from testtools.matchers import Equals, raises
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.python.filepath import FilePath
from twisted.trial.unittest import TestCase as TrialTestCase

from ..config import CONFIG_DB_NAME, REPLICA_RWCAP_BASENAME
from ..model import RandomToken, memory_connect
from ..recover import recover
from ..replicate import replication_service, snapshot, with_replication
from .fixtures import TempDir, TemporaryVoucherStore
from .matchers import equals_database
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


class ReplicationServiceTests(TrialTestCase):
    """
    Tests for ``_ReplicationService``.
    """

    @inlineCallbacks
    def test_replicate(self):
        """
        Making changes to the voucher store while replication is turned on
        causes event-stream objects to be uploaded.
        """

        def get_config(rootpath, portnumfile):
            print("XXX", rootpath)
            return config_from_string(rootpath, portnumfile, "")

        tvs = TemporaryVoucherStore(get_config, lambda: datetime.now())
        tvs.setUp()
        self.addCleanup(tvs._cleanUp)

        rwcap_file = FilePath(tvs.config.get_private_path(REPLICA_RWCAP_BASENAME))
        rwcap_file.parent().makedirs()
        rwcap_file.setContent(b"URL:DIR2:stuff")

        uploads = []
        d = Deferred()
        # we use this to contol when the first upload happens, so that
        # we actually use the queue
        wait_d = Deferred()

        async def uploader(name, get_data):
            uploads.append((name, get_data))
            await wait_d
            nonlocal d
            if d is not None:
                d.callback(None)
                d = None

        other_connection = memory_connect(tvs.config.get_private_path(CONFIG_DB_NAME))
        srv = replication_service(
            tvs.store._connection, other_connection, tvs.store, uploader
        )

        # run the service and produce some fake voucher etc changes
        # that cause "events" to be issued into the database
        srv.startService()

        try:
            tokens = [RandomToken(b64encode(urandom(96))) for _ in range(10)]
            voucher = urlsafe_b64encode(urandom(32))
            srv._store.add(voucher, len(tokens), 1, lambda: tokens)

            self.assertNoResult(d)

            tokens = [RandomToken(b64encode(urandom(96))) for _ in range(10)]
            voucher = urlsafe_b64encode(urandom(32))
            srv._store.add(voucher, len(tokens), 1, lambda: tokens)

            tokens = [RandomToken(b64encode(urandom(96))) for _ in range(10)]
            voucher = urlsafe_b64encode(urandom(32))
            srv._store.add(voucher, len(tokens), 1, lambda: tokens)

            wait_d.callback(None)
            yield d

            # a voucher is "important" so we should have queued some
            # uploads .. but the last two were queued while the first
            # was still uploading, so those last two should be
            # "coalesced" into a single one. That means we expect two
            # uploads
            self.assertEqual(
                [name for name, _ in uploads], ["event-stream-11", "event-stream-33"]
            )

            # since we've uploaded everything, there should be no
            # events in the store
            self.assertEqual(tuple(), tvs.store.get_events().changes)

        finally:
            srv.stopService()


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
        other_connection = memory_connect(tvs.config.get_private_path(CONFIG_DB_NAME))

        async def uploader(name, get_bytes):
            pass

        service = replication_service(
            tvs.store._connection, other_connection, tvs.store, uploader
        )
        service.startService()
        try:
            self.assertThat(tvs.store._connection._replicating, Equals(True))
        finally:
            service.stopService()
