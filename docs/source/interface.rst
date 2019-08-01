Interface
=========

Client
------

When enabled in a Tahoe-LAFS client node,
SecureAccessTokenAuthorizer publishes an HTTP-based interface inside the main Tahoe-LAFS web interface.

``PUT /storage-plugins/privatestorageio-satauthz-v1/payment-reference-number``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent which has submitted a payment to cause the plugin to redeem the payment reference for tokens.
The request body for this endpoint must have the ``application/json`` content-type.
The request body contains a simple json object containing the payment reference number::

  {"payment-reference-number": "<payment reference number>"}

The endpoint responds to such a request with an **OK** HTTP response code if the payment reference number is accepted for processing.
If the payment reference number cannot be accepted at the time of the request then the response code will be anything other than **OK**.

If the response is **OK** then a repeated request with the same body will have no effect.
If the response is not **OK** then a repeated request with the same body will try to accept the number again.

``GET /storage-plugins/privatestorageio-satauthz-v1/payment-reference-number/<payment reference number>``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to monitor the status of the redemption of a payment reference number.
This endpoint accepts no request body.

If the payment reference number is not known then the response is **NOT FOUND**.
For any payment reference number which has previously been submitted,
the response is **OK** with an ``application/json`` content-type response body like::

  {"stage": <integer>,
   "of": <integer>,
   "stage-name": <string>,
   "stage-entered-time": <iso8601 timestamp>
  }

The ``stage`` property indicates how far into redemption the plugin has proceeded.
The ``of`` property indicates how many steps the process involves in total.
The ``stage-name`` property gives a human-meaningful description of the current stage.
The ``stage-entered-time`` property gives the timestamp for the start of the current staged.

``GET /storage-plugins/privatestorageio-satauthz-v1/payment-reference-number``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to retrieve the status of all payment reference numbers.
This endpoint accepts no request body.

The response is **OK** with ``application/json`` content-type response body like::

  {"payment-reference-numbers": [<payment reference status object>, ...]}

The elements of the list are objects like the one returned by issuing a **GET** to a child of this collection resource.
