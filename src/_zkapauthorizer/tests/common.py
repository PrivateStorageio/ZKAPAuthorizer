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
Testing functionality that is specifically related to the test harness
itself.
"""


def skipIf(condition, reason):
    """
    Create a decorate a function to be skipped if the given condition is true.

    :param bool condition: The condition under which to skip.
    :param unicode reason: A reason for the skip.

    :return: A function decorator which will skip the test if the given
        condition is true.
    """
    if condition:
        return _skipper(reason)
    return lambda x: x


def _skipper(reason):
    def wrapper(f):
        def skipIt(self, *a, **kw):
            self.skipTest(reason)
        return skipIt
    return wrapper
