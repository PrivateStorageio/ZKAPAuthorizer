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
Eliot testing helpers.
"""

from functools import wraps
from unittest import SkipTest

from eliot import MemoryLogger
from eliot.testing import check_for_errors, swap_logger


# validate_logging and capture_logging copied from Eliot around 1.11.  We
# can't upgrade past 1.7 because we're not Python 3 compatible.
def validate_logging(assertion, *assertionArgs, **assertionKwargs):
    def decorator(function):
        @wraps(function)
        def wrapper(self, *args, **kwargs):
            skipped = False

            kwargs["logger"] = logger = MemoryLogger()
            self.addCleanup(check_for_errors, logger)
            # TestCase runs cleanups in reverse order, and we want this to
            # run *before* tracebacks are checked:
            if assertion is not None:
                self.addCleanup(
                    lambda: skipped
                    or assertion(self, logger, *assertionArgs, **assertionKwargs)
                )
            try:
                return function(self, *args, **kwargs)
            except SkipTest:
                skipped = True
                raise

        return wrapper

    return decorator


def capture_logging(assertion, *assertionArgs, **assertionKwargs):
    """
    Capture and validate all logging that doesn't specify a L{Logger}.

    See L{validate_logging} for details on the rest of its behavior.
    """

    def decorator(function):
        @validate_logging(assertion, *assertionArgs, **assertionKwargs)
        @wraps(function)
        def wrapper(self, *args, **kwargs):
            logger = kwargs["logger"]
            previous_logger = swap_logger(logger)

            def cleanup():
                swap_logger(previous_logger)

            self.addCleanup(cleanup)
            return function(self, *args, **kwargs)

        return wrapper

    return decorator
