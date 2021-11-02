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
The automated unit test suite.
"""


def _configure_hypothesis():
    """
    Select define Hypothesis profiles and select one based on environment
    variables.
    """
    from os import environ

    from hypothesis import HealthCheck, settings

    base = dict(
        suppress_health_check=[
            # CPU resources available to builds typically varies significantly
            # from run to run making it difficult to determine if "too slow"
            # data generation is a result of the code or the execution
            # environment.  Prevent these checks from (intermittently) failing
            # tests that are otherwise fine.
            HealthCheck.too_slow,
        ],
        # With the same reasoning, disable the test deadline.
        deadline=None,
    )

    settings.register_profile("default", **base)

    settings.register_profile(
        "ci",
        # Make CI runs a little more aggressive in amount of coverage they try
        # to provide.
        max_examples=200,
        **base
    )

    settings.register_profile(
        "big",
        max_examples=10000,
        # The only rule-based state machine we have now is quite simple and
        # can probably be completely explored in about 5 steps.  Give it some
        # headroom beyond that in case I'm wrong but don't let it run to the
        # full 50 because, combined with searching for 10000 successful
        # examples this makes the stateful test take *ages* to complete.
        stateful_step_count=15,
        **base
    )

    profile_name = environ.get("ZKAPAUTHORIZER_HYPOTHESIS_PROFILE", "default")
    settings.load_profile(profile_name)
    print("Loaded profile {}".format(profile_name))


_configure_hypothesis()
