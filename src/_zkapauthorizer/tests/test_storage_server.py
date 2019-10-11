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
    test_and_write_vectors_for_shares,
)
from .fixtures import (
    AnonymousStorageServer,
)
from .storage_common import (
    cleanup_storage_server,
)
from ..api import (
    ZKAPAuthorizerStorageServer,
    MorePassesRequired,
)
from ..storage_common import (
    BYTES_PER_PASS,
    allocate_buckets_message,
    slot_testv_and_readv_and_writev_message,
    required_passes,
    get_sharenums,
    get_allocated_size,
    get_implied_data_length,

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
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

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
        with ``MorePassesRequired``.
        """
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

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
        except MorePassesRequired as e:
            self.assertThat(
                e.required_count,
                Equals(1),
            )
        else:
            self.fail("expected MorePassesRequired, got {}".format(result))


    def _test_extend_mutable_fails_without_passes(self, storage_index, secrets, test_and_write_vectors_for_shares, make_data_vector):
        # Hypothesis causes our storage server to be used many times.  Clean
        # up between iterations.
        cleanup_storage_server(self.anonymous_storage_server)

        tw_vectors = {
            k: v.for_call()
            for (k, v)
            in test_and_write_vectors_for_shares.items()
        }
        sharenums = get_sharenums(tw_vectors)
        allocated_size = get_allocated_size(tw_vectors)
        valid_passes = make_passes(
            self.signing_key,
            slot_testv_and_readv_and_writev_message(storage_index),
            list(
                RandomToken.create()
                for i
                in range(required_passes(BYTES_PER_PASS, sharenums, allocated_size))
            ),
        )

        # Create an initial share to toy with.
        test, read = self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=valid_passes,
                storage_index=storage_index,
                secrets=secrets,
                tw_vectors=tw_vectors,
                r_vector=[],
            ),
        )
        self.assertThat(
            test,
            Equals(True),
            "Server denied initial write.",
        )

        # Try to grow one of the shares by BYTES_PER_PASS which should cost 1
        # pass.
        sharenum = sorted(tw_vectors.keys())[0]
        _, data_vector, new_length = tw_vectors[sharenum]
        current_length = get_implied_data_length(data_vector, new_length)

        do_extend = lambda: self.storage_server.doRemoteCall(
            "slot_testv_and_readv_and_writev",
            (),
            dict(
                passes=[],
                storage_index=storage_index,
                secrets=secrets,
                tw_vectors={
                    sharenum: make_data_vector(current_length),
                },
                r_vector=[],
            ),
        )

        try:
            result = do_extend()
        except MorePassesRequired as e:
            self.assertThat(
                e.required_count,
                Equals(1),
            )
        else:
            self.fail("expected MorePassesRequired, got {}".format(result))

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=test_and_write_vectors_for_shares(),
    )
    def test_extend_mutable_with_new_length_fails_without_passes(self, storage_index, secrets, test_and_write_vectors_for_shares):
        """
        If ``remote_slot_testv_and_readv_and_writev`` is invoked to increase
        storage usage by supplying a ``new_length`` greater than the current
        share size and without supplying passes, the operation fails with
        ``MorePassesRequired``.
        """
        return self._test_extend_mutable_fails_without_passes(
            storage_index,
            secrets,
            test_and_write_vectors_for_shares,
            lambda current_length: (
                [],
                [],
                current_length + BYTES_PER_PASS,
            ),
        )

    @given(
        storage_index=storage_indexes(),
        secrets=tuples(
            write_enabler_secrets(),
            lease_renew_secrets(),
            lease_cancel_secrets(),
        ),
        test_and_write_vectors_for_shares=test_and_write_vectors_for_shares(),
    )
    def test_extend_mutable_with_write_fails_without_passes(self, storage_index, secrets, test_and_write_vectors_for_shares):
        """
        If ``remote_slot_testv_and_readv_and_writev`` is invoked to increase
        storage usage by performing a write past the end of a share without
        supplying passes, the operation fails with ``MorePassesRequired``.
        """
        return self._test_extend_mutable_fails_without_passes(
            storage_index,
            secrets,
            test_and_write_vectors_for_shares,
            lambda current_length: (
                [],
                [(current_length, "x" * BYTES_PER_PASS)],
                None,
            ),
        )
