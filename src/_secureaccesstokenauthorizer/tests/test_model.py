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
    chmod,
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
    assume,
)

from ..model import (
    StoreDirectoryError,
    StoreAddError,
    PaymentReferenceStore,
)

from .strategies import (
    tahoe_configs,
    payment_reference_numbers,
)


class PaymentReferenceStoreTests(TestCase):
    """
    Tests for ``PaymentReferenceStore``.
    """
    @given(tahoe_configs(), payment_reference_numbers())
    def test_get_missing(self, get_config, prn):
        """
        ``PaymentReferenceStore.get`` raises ``KeyError`` when called with a
        payment reference number not previously added to the store.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"node"), b"tub.port")
        store = PaymentReferenceStore(config)
        self.assertThat(
            lambda: store.get(prn),
            raises(KeyError),
        )

    @given(tahoe_configs(), payment_reference_numbers())
    def test_add(self, get_config, prn):
        """
        ``PaymentReferenceStore.get`` returns a ``PaymentReference`` representing
        a payment reference previously added to the store with
        ``PaymentReferenceStore.add``.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"node"), b"tub.port")
        store = PaymentReferenceStore(config)
        store.add(prn)
        payment_reference = store.get(prn)
        self.assertThat(
            payment_reference,
            MatchesStructure(
                number=Equals(prn),
            ),
        )

    @given(tahoe_configs(), payment_reference_numbers())
    def test_add_idempotent(self, get_config, prn):
        """
        More than one call to ``PaymentReferenceStore.add`` with the same argument
        results in the same state as a single call.
        """
        tempdir = self.useFixture(TempDir())
        config = get_config(tempdir.join(b"node"), b"tub.port")
        store = PaymentReferenceStore(config)
        store.add(prn)
        store.add(prn)
        payment_reference = store.get(prn)
        self.assertThat(
            payment_reference,
            MatchesStructure(
                number=Equals(prn),
            ),
        )


    @given(tahoe_configs(), payment_reference_numbers(), payment_reference_numbers())
    def test_unwriteable_store_directory(self, get_config, prn_a, prn_b):
        """
        If the underlying directory in the node configuration is not writeable
        then ``PaymentReferenceStore.add`` raises ``StoreAddError``.
        """
        assume(prn_a != prn_b)
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")
        config = get_config(nodedir, b"tub.port")
        store = PaymentReferenceStore(config)
        # Initialize the underlying directory.
        store.add(prn_a)
        # Mess it up
        chmod(config.get_private_path(store._CONFIG_DIR), 0o500)

        self.assertThat(
            lambda: store.add(prn_b),
            Raises(
                AfterPreprocessing(
                    lambda (type, exc, tb): exc,
                    MatchesAll(
                        IsInstance(StoreAddError),
                        MatchesStructure(
                            reason=MatchesAll(
                                IsInstance(IOError),
                                MatchesStructure(
                                    errno=Equals(EACCES),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        )

    @given(tahoe_configs(), payment_reference_numbers())
    def test_uncreateable_store_directory(self, get_config, prn):
        """
        If the underlying directory in the node configuration cannot be created
        then ``PaymentReferenceStore.add`` raises ``StoreDirectoryError``.
        """
        tempdir = self.useFixture(TempDir())
        nodedir = tempdir.join(b"node")
        config = get_config(nodedir, b"tub.port")
        store = PaymentReferenceStore(config)

        # Create the node directory without permission to create the
        # underlying directory.
        mkdir(nodedir, 0o500)

        self.assertThat(
            lambda: store.add(prn),
            Raises(
                AfterPreprocessing(
                    lambda (type, exc, tb): exc,
                    MatchesAll(
                        IsInstance(StoreDirectoryError),
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
