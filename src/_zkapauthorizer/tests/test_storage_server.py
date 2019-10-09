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
Tests for ``_zkapauthorizer._storage_server``.
"""

from __future__ import (
    absolute_import,
    division,
)

from random import (
    shuffle,
)
from testtools import (
    TestCase,
)
from testtools.matchers import (
    Equals,
    AfterPreprocessing,
    raises,
)
from hypothesis import (
    given,
)
from hypothesis.strategies import (
    integers,
    lists,
    tuples,
)
from privacypass import (
    RandomToken,
    random_signing_key,
)
from foolscap.referenceable import (
    LocalReferenceable,
)

from .privacypass import (
    make_passes,
)
from .strategies import (
    zkaps,
    storage_indexes,
    write_enabler_secrets,
    lease_renew_secrets,
    lease_cancel_secrets,
)
from .fixtures import (
    AnonymousStorageServer,
)
from ..api import (
    ZKAPAuthorizerStorageServer,
    MorePassesRequired,
)
from ..storage_common import (
    BYTES_PER_PASS,
    allocate_buckets_message,
)


class PassValidationTests(TestCase):
    """
    Tests for pass validation performed by ``ZKAPAuthorizerStorageServer``.
    """
    def setUp(self):
        super(PassValidationTests, self).setUp()
        self.anonymous_storage_server = self.useFixture(AnonymousStorageServer()).storage_server
        self.signing_key = random_signing_key()
        self.storage_server = ZKAPAuthorizerStorageServer(
            self.anonymous_storage_server,
            self.signing_key,
        )

    @given(integers(min_value=0, max_value=64), lists(zkaps(), max_size=64))
    def test_validation_result(self, valid_count, invalid_passes):
        """
        ``_get_valid_passes`` returns the number of cryptographically valid passes
        in the list passed to it.
        """
        message = u"hello world"
        valid_passes = make_passes(
            self.signing_key,
            message,
            list(RandomToken.create() for i in range(valid_count)),
        )
        all_passes = valid_passes + list(pass_.text.encode("ascii") for pass_ in invalid_passes)
        shuffle(all_passes)

        self.assertThat(
            self.storage_server._validate_passes(message, all_passes),
            AfterPreprocessing(
                set,
                Equals(set(valid_passes)),
            ),
        )


    def test_allocate_buckets_fails_without_enough_passes(self):
        """
        ``remote_allocate_buckets`` fails with ``MorePassesRequired`` if it is
        passed fewer passes than it requires for the amount of data to be
        stored.
        """
        required_passes = 2
        share_nums = {3, 7}
        allocated_size = int((required_passes * BYTES_PER_PASS) / len(share_nums))
        storage_index = b"0123456789"
        renew_secret = b"x" * 32
        cancel_secret = b"y" * 32
        valid_passes = make_passes(
            self.signing_key,
            allocate_buckets_message(storage_index),
            list(RandomToken.create() for i in range(required_passes - 1)),
        )

        allocate_buckets = lambda: self.storage_server.doRemoteCall(
            "allocate_buckets",
            (valid_passes,
             storage_index,
             renew_secret,
             cancel_secret,
             share_nums,
             allocated_size,
             LocalReferenceable(None),
            ),
            {},
        )
        self.assertThat(
            allocate_buckets,
            raises(MorePassesRequired),
        )


    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
    )
    def test_create_mutable_fails_without_passes(self, storage_index, secrets):
        """
        If ``remote_slot_testv_and_readv_and_writev`` is invoked to perform
        initial writes on shares without supplying passes, the operation fails
        with ``LeaseRenewalRequired``.
        """
        data = b"01234567"
        offset = 0
        sharenum = 0
        mutable_write = lambda: self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=[],
                storage_index=storage_index,
                secrets=secrets,
                tw_vectors={
                    sharenum: ([], [(offset, data)], None),
                },
                r_vector=[],
            ),
        )

        try:
            result = mutable_write()
        except MorePassesRequired:
            pass
        else:
            self.fail("expected LeaseRenewalRequired, got {}".format(result))

    # TODO
    # a write that increases the storage cost of the share requires passes too
