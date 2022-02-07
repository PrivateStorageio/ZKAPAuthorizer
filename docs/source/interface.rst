Interface
=========

Client
------

When enabled in a Tahoe-LAFS client node,
ZKAPAuthorizer publishes an HTTP-based interface inside the main Tahoe-LAFS web interface.

All endpoints in the interface require an authorization token.
Without the token,
requests will receive an HTTP UNAUTHORIZED (401) response.

To be authorized to access the resources at the endpoints,
requests must include the correct secret token in the value for **Authorization** in the request header.
For example, if the secret token is ``ABCDEF``::

  Authorization: tahoe-lafs ABCDEF

The correct value for the token can be read from the Tahoe-LAFS node's ``private/api_auth_token`` file.

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

  { "version": 1
  , "number": <string>
  , "expected-tokens": <integer>
  , "created": <iso8601 timestamp>
  , "state": <state object>
  }

The ``version`` property indicates the semantic version of the data being returned.
When properties are removed or the meaning of a property is changed,
the value of the ``version`` property will be incremented.
The addition of new properties is **not** accompanied by a bumped version number.

The ``number`` property merely indicates the voucher which was requested.
The ``expected-tokens`` property indicates the total number of ZKAPs for which the client intends to redeem the voucher.
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

The *started* timestamp gives the time when the most recent redemption attempt began.
The integer *counter* value has the same meaning as it does for the *pending* state.

::

  { "name": "redeemed"
  , "finished": <iso8601 timestamp>
  , "token-count": <number>
  }

The *finished* timestamp gives the time when redemption completed successfully.
The integer *token-count* gives the number tokens for which the voucher was redeemed.

::

  { "name": "double-spend"
  , "finished": <iso8601 timestamp>
  }

The *finished* timestamp gives the time when the double-spend error was encountered.

::

  { "name": "unpaid"
  , "finished": <iso8601 timestamp>
  }

The *finished* timestamp gives the time when the unpaid error was encountered.

::

  { "name": "error"
    "finished": <iso8601 timestamp>
  , "details": <text>
  }

The *finished* timestamp gives the time when this other error condition was encountered.
The *details* string may give additional details about what the error was.

``GET /storage-plugins/privatestorageio-zkapauthz-v1/voucher``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to retrieve the status of all vouchers.
This endpoint accepts no request body.

The response is **OK** with ``application/json`` content-type response body like::

  {"vouchers": [<voucher status object>, ...]}

The elements of the list are objects like the one returned by issuing a **GET** to a child of this collection resource.

``GET /storage-plugins/privatestorageio-zkapauthz-v1/lease-maintenance``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to retrieve information about automatic spending for lease maintenance.

This endpoint accepts no request body.

The response is **OK** with ``application/json`` content-type response body like::

  { "spendable": <integer>
  , "lease-maintenance-spending": <spending object>
  }

The value associated with ``spendable`` gives the number of unblinded tokens in the node's database which can actually be spent.

The ``<spending object>`` may be ``null`` if the lease maintenance process has never run.
If it has run,
``<spending object>`` has two properties:

 * ``when``: associated with an ISO8601 datetime string giving the approximate time the process ran
 * ``count``: associated with a number giving the number of passes which would need to be spent to renew leases on all stored objects seen during the lease maintenance activity

``POST /storage-plugins/privatestorageio-zkapauthz-v1/calculate-price``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an agent to calculate the number of ZKAPs it will cost to store a collection of files of specified sizes.
This is intended as the basis for tools which aid in user understanding of the cost of their actions.

The request body must be ``application/json`` encoded and contain an object like::

  { "version": 1
  , "sizes: [ <integer>, ... ]
  }

The ``version`` property must currently be **1**.
The ``sizes`` property is a list of integers giving file sizes in bytes.

The response is **OK** with ``application/json`` content-type response body like::

  { "price": <integer>, "period": <integer> }

The ``price`` property gives the number of ZKAPs which would have to be spent to store files of the given sizes.
The ``period`` property gives the number of seconds those files would be stored by spending that number of ZKAPs.

The price obtained this way is valid in two scenarios.
First,
the case where none of the files have been uploaded yet.
In this case uploading the files and storing them for **period** seconds will cost **price** ZKAPs.
Second,
the case where the files have already been uploaded but their leases need to be renewed.
In this case, renewing the leases so they last until **period** seconds after the current time will cost **price** ZKAPs.
Note that in this case any lease time currently remaining on any files has no bearing on the calculated price.
