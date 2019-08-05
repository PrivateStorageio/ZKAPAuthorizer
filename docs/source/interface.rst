Interface
=========

Client
------

When enabled in a Tahoe-LAFS client node,
ZKAPAuthorizer publishes an HTTP-based interface inside the main Tahoe-LAFS web interface.

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

  {"value": <string>}

The ``value`` property merely indicates the voucher which was requested.
Further properties will be added to this response in the near future.

``GET /storage-plugins/privatestorageio-zkapauthz-v1/voucher``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This endpoint allows an external agent to retrieve the status of all vouchers.
This endpoint accepts no request body.

The response is **OK** with ``application/json`` content-type response body like::

  {"vouchers": [<voucher status object>, ...]}

The elements of the list are objects like the one returned by issuing a **GET** to a child of this collection resource.
