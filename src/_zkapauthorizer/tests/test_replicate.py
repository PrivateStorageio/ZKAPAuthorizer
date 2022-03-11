"""
Tests for the replication system in ``_zkapauthorizer.replicate``.
"""

from asyncio import run
from io import BytesIO
from sqlite3 import OperationalError, ProgrammingError, connect

from fixtures import TempDir
from hypothesis import given, note
from hypothesis.strategies import just, lists, one_of, tuples
from testtools import TestCase
from testtools.matchers import AfterPreprocessing, Equals, IsInstance, raises
from testtools.twistedsupport import failed
from twisted.internet.defer import Deferred

from ..config import REPLICA_RWCAP_BASENAME
from ..recover import recover
from ..replicate import (
    ReplicationAlreadySetup,
    event_stream_statement,
    setup_tahoe_lafs_replication,
    with_replication,
)
from ..tahoe import MemoryGrid, attenuate_writecap
from .matchers import equals_database, matches_capability
from .sql import create_table
from .strategies import (
    api_auth_tokens,
    deletes,
    inserts,
    sql_identifiers,
    tables,
    tahoe_configs,
    updates,
)


class ReplicationConnectionTests(TestCase):
    """
    Tests for the SQLite3 connection-like object returned by
    ``with_replication``.
    """

    def test_close(self):
        """
        The connection object and its cursors can be closed.
        """
        conn = with_replication(connect(":memory:"))
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
        conn = with_replication(connect(dbpath))
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
        conn = with_replication(connect(dbpath))
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
        conn = with_replication(connect(":memory:"))
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
        conn = with_replication(connect(":memory:"))
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
        conn_a = with_replication(connect(dbpath_a))
        with conn_a:
            cursor = conn_a.cursor()
            cursor.execute('CREATE TABLE "foo" ("a" INT)')
            cursor.execute('INSERT INTO "foo" VALUES (?)', (1,))

        snapshot = conn_a.snapshot()

        dbpath_b = self.useFixture(TempDir()).join("db.sqlite")
        conn_b = with_replication(connect(dbpath_b))

        with conn_b:
            recover(BytesIO(snapshot), conn_b.cursor())

        self.assertThat(
            conn_a,
            equals_database(conn_b),
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


class EventStreamStatementTests(TestCase):
    """
    Tests for ``event_stream_statement``.
    """

    @given(
        tuples(sql_identifiers(), tables()).flatmap(
            lambda name_and_table: tuples(
                just(name_and_table),
                lists(inserts(*name_and_table)),
                one_of(
                    [
                        inserts(*name_and_table),
                        updates(*name_and_table),
                        deletes(*name_and_table),
                    ]
                ),
            ),
        ),
    )
    def test_same_modification(self, schema_and_inserts_and_statement):
        """
        The SQL statement returned by ``event_stream_statement`` makes the same
        changes to a database as the original statement and arguments.
        """
        (name, table), inserts, statement = schema_and_inserts_and_statement

        db_a = connect(":memory:")
        db_b = connect(":memory:")

        for db in [db_a, db_b]:
            db.execute(create_table(name, table))

        # Prepare the database with some data that could be modified.
        for insert in inserts:
            db_a.execute(insert.statement(), insert.arguments())
            db_b.execute(insert.statement(), insert.arguments())

        note(statement.statement())
        sql = event_stream_statement(db_a, statement.statement(), statement.arguments())
        note(sql)

        # Execute the original and "bound" forms of the statement against the
        # two databases so we can observe their consequences.
        db_a.execute(statement.statement(), statement.arguments())
        db_b.execute(sql)

        # The consequences should be the same.
        self.assertThat(
            db_a,
            equals_database(db_b),
        )
