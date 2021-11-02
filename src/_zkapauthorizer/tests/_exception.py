# Copyright (c) 2009-2012 testtools developers.
#
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

__all__ = [
    "MatchesExceptionType",
    "Raises",
    "raises",
]

import sys

from testtools.content import TracebackContent
from testtools.matchers import Matcher, Mismatch


def _is_exception(exc):
    return isinstance(exc, BaseException)


def _is_user_exception(exc):
    return isinstance(exc, Exception)


class MatchesExceptionType(Matcher):
    """
    Match an exc_info tuple against an exception type.
    """

    def __init__(self, exception_type):
        """
        Create a MatchesException that will match exc_info's for exception.

        :param exception: An exception type.
        """
        Matcher.__init__(self)
        self.expected = exception_type

    def match(self, other):
        if type(other) != tuple:
            return Mismatch("{!r} is not an exc_info tuple".format(other))
        expected_class = self.expected
        etype, evalue, etb = other
        if not issubclass(etype, expected_class):
            return Mismatch(
                "{!r} is an instance of {}, expected an instance of {}.".format(
                    evalue,
                    etype,
                    expected_class,
                ),
                dict(
                    traceback=TracebackContent(other, None),
                ),
            )

    def __str__(self):
        return "MatchesExceptionType({!r})".format(self.expected)


class Raises(Matcher):
    """Match if the matchee raises an exception when called.

    Exceptions which are not subclasses of Exception propogate out of the
    Raises.match call unless they are explicitly matched.
    """

    def __init__(self, exception_matcher):
        """
        Create a Raises matcher.

        :param exception_matcher: Validator for the exception raised by
            matchee. The exc_info tuple for the exception raised is passed
            into that matcher.
        """
        self.exception_matcher = exception_matcher

    def match(self, matchee):
        try:
            result = matchee()
            return Mismatch("%r returned %r" % (matchee, result))
        # Catch all exceptions: Raises() should be able to match a
        # KeyboardInterrupt or SystemExit.
        except:
            exc_info = sys.exc_info()
            mismatch = self.exception_matcher.match(exc_info)
            exc_type = exc_info[1]
            # It's safer not to keep the traceback around.
            del exc_info
            if mismatch:
                # The exception did not match, or no explicit matching logic was
                # performed. If the exception is a non-user exception then
                # propagate it.
                if _is_exception(exc_type) and not _is_user_exception(exc_type):
                    raise
                return mismatch
        return None

    def __str__(self):
        return "Raises()"


def raises(exception_type):
    """Make a matcher that checks that a callable raises an exception.

    This is a convenience function, exactly equivalent to::

        return Raises(MatchesExceptionType(exception_type))

    See `Raises` and `MatchesExceptionType` for more information.
    """
    return Raises(MatchesExceptionType(exception_type))
