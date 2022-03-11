"""
Tests for the replication system in ``_zkapauthorizer.replicate``.
"""

from sqlite3 import OperationalError, connect

from fixtures import TempDir
from testtools import TestCase
from testtools.matchers import Equals, raises

from ..recover import recover
from ..replicate import connect_with_replication
from .matchers import equals_database


class ReplicationConnectionTests(TestCase):
    """
    Tests for the SQLite3 connection-like object returned by
    ``connect_with_replication``.
    """

    def test_not_openable(self):
        """
        If the underlying database cannot be opened then the normal SQLite3
        exception is propagated.
        """

        class BogusDatabase(Exception):
            pass

        def bogus_connect(path):
            raise BogusDatabase(path)

        bogus_path = "/no/such/directory/database.sql"

        self.assertThat(
            lambda: connect_with_replication(bogus_connect, bogus_path),
            raises(BogusDatabase(bogus_path)),
        )

    def test_context_manager_success(self):
        """
        The connection object is a context manager that commits the transaction
        when the managed block completes normally.
        """
        dbpath = self.useFixture(TempDir()).join("db.sqlite")
        conn = connect_with_replication(connect, dbpath)
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
        conn = connect_with_replication(connect, dbpath)
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
        conn = connect_with_replication(connect, ":memory:")
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
        conn = connect_with_replication(connect, ":memory:")
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
        conn_a = connect_with_replication(connect, dbpath_a)
        with conn_a:
            cursor = conn_a.cursor()
            cursor.execute('CREATE TABLE "foo" ("a" INT)')
            cursor.execute('INSERT INTO "foo" VALUES (?)', (1,))

        snapshot = conn_a.snapshot()

        dbpath_b = self.useFixture(TempDir()).join("db.sqlite")
        conn_b = connect_with_replication(connect, dbpath_b)

        with conn_b:
            recover(snapshot, conn_b.cursor())

        self.assertThat(
            conn_a,
            equals_database(conn_b),
        )
