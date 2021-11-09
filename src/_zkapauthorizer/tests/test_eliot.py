# Copyright PrivateStorage.io, LLC
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
Tests for eliot helpers.
"""
from __future__ import absolute_import, division, print_function, unicode_literals

import attr
from eliot import start_action
from eliot.testing import assertHasAction
from testtools import TestCase

from ..eliot import register_attr_exception
from .eliot import capture_logging


class RegisterExceptionTests(TestCase):
    """
    Tests for :py:`register_attr_exception`.
    """

    @capture_logging(None)
    def test_register(self, logger):
        @register_attr_exception
        @attr.s(auto_exc=True)
        class E(Exception):
            field = attr.ib()

        try:
            with start_action(action_type="test:action"):
                raise E(field="value")
        except E:
            pass

        assertHasAction(
            self, logger, "test:action", False, endFields={"field": "value"}
        )
