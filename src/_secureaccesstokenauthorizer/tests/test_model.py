# coding: utf-8
# Copyright 2019 PrivateStorage.io, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Tests for ``_secureaccesstokenauthorizer.model``.
"""

from os import (
    mkdir,
)
from errno import (
    EACCES,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    AfterPreprocessing,
    MatchesStructure,
    MatchesAll,
    Equals,
    Raises,
    IsInstance,
    raises,
)

from fixtures import (
    TempDir,
)

from hypothesis import (
    given,
)
from hypothesis.strategies import (
    lists,
)

from twisted.python.filepath import (
    FilePath,
)

from ..model import (
    SchemaError,
    StoreOpenError,
    VoucherStore,
    Voucher,
    open_and_initialize,
    memory_connect,
)

from .strategies import (
    tahoe_configs,
    vouchers,
)


class VoucherStoreTests(TestCase):
    """
    Tests for ``VoucherStore``.
    """
    def test_create_mismatched_schema(self):
        """
        ``open_and_initialize`` raises ``SchemaError`` if asked for a database
        with a schema version other than it can create.
        """
        tempdir = self.useFixture(TempDir())
        dbpath = tempdir.join(b"db.sqlite3")
        self.assertThat(
            lambda: open_and_initialize(
                FilePath(dbpath),
                required_schema_version=100,
            ),
            raises(SchemaError),
        )


    @given(tahoe_configs(), vouchers())
    def test_get_missing(self, get_config, prn):
        """
        ``VoucherStore.get`` raises ``KeyError`` when called with a
        voucher not previously added to the store.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"node"), b"tub.port")
        store = VoucherStore.from_node_config(
            config,
            memory_connect,
        )
        self.assertThat(
            lambda: store.get(prn),
            raises(KeyError),
        )

    @given(tahoe_configs(), vouchers())
    def test_add(self, get_config, prn):
        """
        ``VoucherStore.get`` returns a ``Voucher`` representing a voucher
        previously added to the store with ``VoucherStore.add``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"node"), b"tub.port")
        store = VoucherStore.from_node_config(
            config,
            memory_connect,
        )
        store.add(prn)
        voucher = store.get(prn)
        self.assertThat(
            voucher,
            MatchesStructure(
                number=Equals(prn),
            ),
        )

    @given(tahoe_configs(), vouchers())
    def test_add_idempotent(self, get_config, prn):
        """
        More than one call to ``VoucherStore.add`` with the same argument results
        in the same state as a single call.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"node"), b"tub.port")
        store = VoucherStore.from_node_config(
            config,
            memory_connect,
        )
        store.add(prn)
        store.add(prn)
        voucher = store.get(prn)
        self.assertThat(
            voucher,
            MatchesStructure(
                number=Equals(prn),
            ),
        )


    @given(tahoe_configs(), lists(vouchers()))
    def test_list(self, get_config, prns):
        """
        ``VoucherStore.list`` returns a ``list`` containing a ``Voucher`` object
        for each voucher previously added.
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")
        config = get_config(nodedir, b"tub.port")
        store = VoucherStore.from_node_config(
            config,
            memory_connect,
        )

        for prn in prns:
            store.add(prn)

        self.assertThat(
            store.list(),
            AfterPreprocessing(
                lambda refs: set(ref.number for ref in refs),
                Equals(set(prns)),
            ),
        )


    @given(tahoe_configs())
    def test_uncreateable_store_directory(self, get_config):
        """
        If the underlying directory in the node configuration cannot be created
        then ``VoucherStore.from_node_config`` raises ``StoreOpenError``.
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")

        # Create the node directory without permission to create the
        # underlying directory.
        mkdir(nodedir, 0o500)

        config = get_config(nodedir, b"tub.port")

        self.assertThat(
            lambda: VoucherStore.from_node_config(
                config,
                memory_connect,
            ),
            Raises(
                AfterPreprocessing(
                    lambda (type, exc, tb): exc,
                    MatchesAll(
                        IsInstance(StoreOpenError),
                        MatchesStructure(
                            reason=MatchesAll(
                                IsInstance(OSError),
                                MatchesStructure(
                                    errno=Equals(EACCES),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )


    @given(tahoe_configs())
    def test_unopenable_store(self, get_config):
        """
        If the underlying database file cannot be opened then
        ``VoucherStore.from_node_config`` raises ``StoreOpenError``.
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")

        config = get_config(nodedir, b"tub.port")

        # Create the underlying database file.
        store = VoucherStore.from_node_config(config)

        # Prevent further access to it.
        store.database_path.chmod(0o000)

        self.assertThat(
            lambda: VoucherStore.from_node_config(
                config,
            ),
            raises(StoreOpenError),
        )


class VoucherTests(TestCase):
    """
    Tests for ``Voucher``.
    """
    @given(vouchers())
    def test_json_roundtrip(self, prn):
        """
        ``Voucher.to_json . Voucher.from_json → id``
        """
        ref = Voucher(prn)
        self.assertThat(
            Voucher.from_json(ref.to_json()),
            Equals(ref),
        )
