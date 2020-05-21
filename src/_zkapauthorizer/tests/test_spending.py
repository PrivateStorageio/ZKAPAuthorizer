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
Tests for ``_zkapauthorizer.spending``.
"""

from testtools import (
    TestCase,
)
from testtools.matchers import (
    Always,
    MatchesAll,
    MatchesStructure,
    HasLength,
)
from testtools.twistedsupport import (
    succeeded,
)

from hypothesis import (
    given,
)

from twisted.python.filepath import (
    FilePath,
)

from .strategies import (
    vouchers,
    pass_counts,
    posix_safe_datetimes,
)
from .matchers import (
    Provides,
)
from ..model import (
    VoucherStore,
    open_and_initialize,
    memory_connect,
)
from ..controller import (
    DummyRedeemer,
    PaymentController,
)
from ..spending import (
    IPassGroup,
    SpendingController,
)

class PassGroupTests(TestCase):
    """
    Tests for ``IPassGroup`` and the factories that create them.
    """
    @given(vouchers(), pass_counts(), posix_safe_datetimes())
    def test_get(self, voucher, num_passes, now):
        """
        ``IPassFactory.get`` returns an ``IPassGroup`` provider containing the
        requested number of passes.
        """
        redeemer = DummyRedeemer()
        here = FilePath(u".")
        store = VoucherStore(
            pass_value=2 ** 15,
            database_path=here,
            now=lambda: now,
            connection=open_and_initialize(here, memory_connect),
        )
        # Make sure there are enough tokens for us to extract!
        self.assertThat(
            PaymentController(
                store,
                redeemer,
                # Have to pass it here or to redeem, doesn't matter which.
                default_token_count=num_passes,
                # No value in splitting it into smaller groups in this case.
                # Doing so only complicates the test by imposing a different
                # minimum token count requirement (can't have fewer tokens
                # than groups).
                num_redemption_groups=1,
            ).redeem(
                voucher,
            ),
            succeeded(Always()),
        )

        pass_factory = SpendingController(
            extract_unblinded_tokens=store.extract_unblinded_tokens,
            tokens_to_passes=redeemer.tokens_to_passes,
        )

        group = pass_factory.get(u"message", num_passes)
        self.assertThat(
            group,
            MatchesAll(
                Provides([IPassGroup]),
                MatchesStructure(
                    passes=HasLength(num_passes),
                ),
            ),
        )
