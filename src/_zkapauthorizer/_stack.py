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

from contextlib import (
    contextmanager,
)

try:
    from resource import (
        RLIMIT_STACK,
        getrlimit,
        setrlimit,
    )
except ImportError:
    # Not available on Windows, unfortunately.
    RLIMIT_STACK = object()
    def getrlimit(which):
        return (-1, -1)
    def setrlimit(which, what):
        pass



@contextmanager
def less_limited_stack():
    """
    A context manager which removes the resource limit on stack size, to the
    extent possible, for execution of the context.

    More precisely, the soft stack limit is raised to the hard limit.
    """
    soft, hard = getrlimit(RLIMIT_STACK)
    # We can raise the soft limit to the hard limit and no higher.
    setrlimit(RLIMIT_STACK, (hard, hard))
    yield
    setrlimit(RLIMIT_STACK, (soft, hard))
