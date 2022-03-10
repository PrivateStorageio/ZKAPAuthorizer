# Copyright 2022 PrivateStorage.io, LLC
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
A library for functional implementations of useful kinds of control flow.
"""

from twisted.internet.defer import inlineCallbacks, returnValue


@inlineCallbacks
def bracket(first, last, between):
    """
    Invoke an action between two other actions.

    :param first: A no-argument function that may return a Deferred.  It is
        called first.

    :param last: A no-argument function that may return a Deferred.  It is
        called last.

    :param between: A no-argument function that may return a Deferred.  It is
        called after ``first`` is done and completes before ``last`` is called.

    :return Deferred: A ``Deferred`` which fires with the result of
        ``between``.
    """
    yield first()
    try:
        result = yield between()
    except GeneratorExit:
        raise
    except:
        yield last()
        raise
    else:
        yield last()
        returnValue(result)
