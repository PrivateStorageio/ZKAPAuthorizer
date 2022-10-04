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
    "__version__",
    "NAME",
]


# Hotfix Tahoe-LAFS #3883
from allmydata import stats

stats.eventually = lambda f: f()

# The identifier for this plugin.  This appears in URLs for resources the
# client plugin exposes, configuration files, etc.
NAME = "privatestorageio-zkapauthz-v2"

__version__ = "2022.8.21"
