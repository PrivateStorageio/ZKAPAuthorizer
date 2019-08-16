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
Tests for ``_zkapauthorizer.controller``.
"""

from testtools import (
    TestCase,
)
from testtools.matchers import (
    Equals,
)

from fixtures import (
    TempDir,
)

from hypothesis import (
    given,
)

from ..controller import (
    NonRedeemer,
    DummyRedeemer,
    PaymentController,
)

from ..model import (
    memory_connect,
    VoucherStore,
)

from .strategies import (
    tahoe_configs,
    vouchers,
)

class PaymentControllerTests(TestCase):
    """
    Tests for ``PaymentController``.
    """
    @given(tahoe_configs(), vouchers())
    def test_not_redeemed_while_redeeming(self, get_config, voucher):
        """
        A ``Voucher`` is not marked redeemed before ``IRedeemer.redeem``
        completes.
        """
        tempdir = self.useFixture(TempDir())
        store = VoucherStore.from_node_config(
            get_config(
                tempdir.join(b"node"),
                b"tub.port",
            ),
            connect=memory_connect,
        )
        controller = PaymentController(
            store,
            NonRedeemer(),
        )
        controller.redeem(voucher)

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher.redeemed,
            Equals(False),
        )

    @given(tahoe_configs(), vouchers())
    def test_redeemed_after_redeeming(self, get_config, voucher):
        tempdir = self.useFixture(TempDir())
        store = VoucherStore.from_node_config(
            get_config(
                tempdir.join(b"node"),
                b"tub.port",
            ),
            connect=memory_connect,
        )
        controller = PaymentController(
            store,
            DummyRedeemer(),
        )
        controller.redeem(voucher)

        persisted_voucher = store.get(voucher)
        self.assertThat(
            persisted_voucher.redeemed,
            Equals(True),
        )
