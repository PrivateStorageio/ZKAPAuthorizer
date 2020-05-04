Interface
=========

Client
------

When enabled in a Tahoe-LAFS client node,
ZKAPAuthorizer publishes an HTTP-based interface inside the main Tahoe-LAFS web interface.

``GET /storage-plugins/privatestorageio-zkapauthz-v1/version``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint returns the version of the ZKAPAuthorizer Python package in use by the Tahoe-LAFS client node.

The response is **OK** with an ``application/json`` **Content-Type**::

  { "version": <string>
  }

``PUT /storage-plugins/privatestorageio-zkapauthz-v1/voucher``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent which has submitted a payment to cause the plugin to redeem the voucher for tokens.
The request body for this endpoint must have the ``application/json`` content-type.
The request body contains a simple json object containing the voucher::

  {"voucher": "<voucher>"}

The endpoint responds to such a request with an **OK** HTTP response code if the voucher is accepted for processing.
If the voucher cannot be accepted at the time of the request then the response code will be anything other than **OK**.

If the response is **OK** then a repeated request with the same body will have no effect.
If the response is not **OK** then a repeated request with the same body will try to accept the number again.

``GET /storage-plugins/privatestorageio-zkapauthz-v1/voucher/<voucher>``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to monitor the status of the redemption of a voucher.
This endpoint accepts no request body.

If the voucher is not known then the response is **NOT FOUND**.
For any voucher which has previously been submitted,
the response is **OK** with an ``application/json`` content-type response body like::

  { "number": <string>
  , "expected-tokens": <integer>
  , "created": <iso8601 timestamp>
  , "state": <state object>
  , "version": 1
  }

The ``number`` property merely indicates the voucher which was requested.
The ``expected-tokens`` property indicates the total number of ZKAPs the client for which the client intends to redeem the voucher.
Vouchers created using old versions of ZKAPAuthorizer will have a best-guess value here because the real value was not recorded.
The ``created`` property indicates when the voucher was first added to the node.
The ``state`` property is an object that gives more details about the current state of the voucher.
The following values are possible::

  { "name": "pending"
  , "counter": <integer>
  }

The integer *counter* value indicates how many successful sub-redemptions have completed for this voucher.

::

  { "name": "redeeming"
  , "started": <iso8601 timestamp>
  , "counter": <integer>
  }

The integer *counter* value has the same meaning as it does for the *pending* state.

::

  { "name": "redeemed"
  , "finished": <iso8601 timestamp>
  , "token-count": <number>
  }

::

  { "name": "double-spend"
  , "finished": <iso8601 timestamp>
  }

::

  { "name": "unpaid"
  , "finished": <iso8601 timestamp>
  }

::

  { "name": "error"
    "finished": <iso8601 timestamp>
  , "details": <text>
  }

The ``version`` property indicates the semantic version of the data being returned.
When properties are removed or the meaning of a property is changed,
the value of the ``version`` property will be incremented.
The addition of new properties is **not** accompanied by a bumped version number.

``GET /storage-plugins/privatestorageio-zkapauthz-v1/voucher``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to retrieve the status of all vouchers.
This endpoint accepts no request body.

The response is **OK** with ``application/json`` content-type response body like::

  {"vouchers": [<voucher status object>, ...]}

The elements of the list are objects like the one returned by issuing a **GET** to a child of this collection resource.

``GET /storage-plugins/privatestorageio/zkapauthz-v1/unblinded-token``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to retrieve unused unblinded tokens present in the node's database.
Unblinded tokens are returned in a stable order.
This order matches the order in which tokens will be used by the system.
This endpoint accepts several query arguments:

  * limit: An integer limiting the number of unblinded tokens to retrieve.
  * position: A string which can be compared against unblinded token values.
    Only unblinded tokens which sort as great than this value are returned.

This endpoint accepts no request body.

The response is **OK** with ``application/json`` content-type response body like::

  { "total": <integer>
  , "unblinded-tokens": [<unblinded token string>, ...]
  , "lease-maintenance-spending": <spending object>
  }

The ``<spending object>`` may be ``null`` if the lease maintenance process has never run.
If it has run,
``<spending object>`` has two properties:

 * ``when``: associated with an ISO8601 datetime string giving the approximate time the process ran
 * ``count``: associated with a number giving the number of passes which would need to be spent to renew leases on all stored objects seen during the lease maintenance activity

``POST /storage-plugins/privatestorageio/zkapauthz-v1/unblinded-token``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to insert new unblinded tokens into the node's database.
This allows for restoration of previously backed-up tokens in case the node is lost.
Tokens inserted with this API will be used after any tokens already in the database and in the order they appear in the given list.

The request body must be ``application/json`` encoded and contain an object like::

  { "unblinded-tokens": [<unblinded token string>, ...]
  }

The response is **OK** with ``application/json`` content-type response body like::

  { }
