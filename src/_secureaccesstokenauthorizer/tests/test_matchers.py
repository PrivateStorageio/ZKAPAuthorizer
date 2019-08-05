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
Tests for ``_secureaccesstokenauthorizer.tests.matchers``.
"""

from zope.interface import (
    Interface,
    implementer,
)

from testtools import (
    TestCase,
)
from testtools.matchers import (
    Not,
    Is,
)

from .matchers import (
    Provides,
    returns,
)


class IX(Interface):
    pass


class IY(Interface):
    pass


@implementer(IX, IY)
class X(object):
    pass


@implementer(IY)
class Y(object):
    pass


class ProvidesTests(TestCase):
    """
    Tests for ``Provides``.
    """
    def test_match(self):
        """
        ``Provides.match`` returns ``None`` when the given object provides all of
        the configured interfaces.
        """
        self.assertThat(
            Provides([IX, IY]).match(X()),
            Is(None),
        )

    def test_mismatch(self):
        """
        ``Provides.match`` does not return ``None`` when the given object provides
        none of the configured interfaces.
        """
        self.assertThat(
            Provides([IX, IY]).match(Y()),
            Not(Is(None)),
        )


class ReturnsTests(TestCase):
    """
    Tests for ``returns``.
    """
    def test_match(self):
        """
        ``returns(m)`` returns a matcher that matches when the given object
        returns a value matched by ``m``.
        """
        result = object()
        self.assertThat(
            returns(Is(result)).match(lambda: result),
            Is(None),
        )

    def test_mismatch(self):
        """
        ``returns(m)`` returns a matcher that does not match when the given object
        returns a value not matched by ``m``.
        """
        result = object()
        other = object()
        self.assertThat(
            returns(Is(result)).match(lambda: other),
            Not(Is(None)),
        )
