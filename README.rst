Secure Access Token Authorizer
==============================

|coverage|_

What is this?
-------------

Secure Access Token Authorizer is a `Tahoe-LAFS`_ storage-system plugin which authorizes storage operations based on privacy-respecting tokens.

Such tokens derive from `PrivacyPass`_.
They allow a Tahoe-LAFS client to prove it has a right to access without revealing additional information.

Copyright
---------

   Copyright 2019 PrivateStorage.io, LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

.. _Tahoe-LAFS: https://tahoe-lafs.org/

.. _PrivacyPass: https://privacypass.github.io/

.. |coverage| image:: https://codecov.io/gh/PrivateStorageio/SecureAccessTokenAuthorizer/branch/master/graph/badge.svg
.. _coverage: https://codecov.io/gh/PrivateStorageio/SecureAccessTokenAuthorizer
