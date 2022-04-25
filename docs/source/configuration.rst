Configuration
=============

Client
------

To enable the plugin at all, add its name to the list of storage plugins in the Tahoe-LAFS configuration
(``tahoe.cfg`` in the relevant node directory)::

  [client]
  storage.plugins = privatestorageio-zkapauthz-v2

Then configure the plugin as desired in the ``storageclient.plugins.privatestorageio-zkapauthz-v2`` section.

redeemer
~~~~~~~~

This item configures the voucher redeemer the client will use to redeem vouchers submitted to it.
The ``dummy`` value is useful for testing purposes only.

For example::

  [storageclient.plugins.privatestorageio-zkapauthz-v2]
  redeemer = dummy
  issuer-public-key = YXNkYXNkYXNkYXNkYXNkCg==

The value of the ``issuer-public-key`` item is included as-is as the public key in the successful redemption response.

A ``redeemer`` value of ``ristretto`` causes the client to speak Ristretto-flavored PrivacyPass to an issuer server.
In this case the ``ristretto-issuer-root-url`` item is also required.
The client uses this URL to determine the server to which to send redemption requests.
Additionally,
the client will only interact with storage servers which announce the same issuer URL.

For example::

  [storageclient.plugins.privatestorageio-zkapauthz-v2]
  redeemer = ristretto
  ristretto-issuer-root-url = https://issuer.example.invalid/


The client can also be configured with the value of a single pass::

    [storageclient.plugins.privatestorageio-zkapauthz-v2]
    pass-value = 1048576

The value given here must agree with the value servers use in their configuration or the storage service will be unusable.

The client can also be configured with the number of passes to expect in exchange for one voucher::

  [storageclient.plugins.privatestorageio-zkapauthz-v2]
  default-token-count = 32768

The value given here must agree with the value the issuer uses in its configuration or redemption may fail.

allowed-public-keys
~~~~~~~~~~~~~~~~~~~

Regardless of which redeemer is selected,
the client must also be configured with the public part of the issuer key pair which it will allow to sign tokens::

  [storageclient.plugins.privatestorageio-zkapauthz-v2]
  allowed-public-keys = AAAA...,BBBB...,CCCC...

The ``allowed-public-keys`` value is a comma-separated list of encoded public keys.
When tokens are received from an issuer during redemption,
these are the only public keys which will satisfy the redeemer and cause the tokens to be made available to the client to be spent.
Tokens received with any other public key will be sequestered and will *not* be spent until some further action is taken.

lease.crawl-interval.mean
~~~~~~~~~~~~~~~~~~~~~~~~~

This item controls the frequency at which the lease maintenance crawler runs.
The lease maintenance crawler visits all shares and renews their leases if necessary.
The crawler will run at random intervals.
The client will try to make the average (mean) interval between runs equal to this setting.
The value is an integer number of seconds.
For example to run on average every 26 days::

  [storageclient.plugins.privatestorageio-zkapauthz-v2]
  lease.crawl-interval.mean = 2246400


lease.crawl-interval.range
~~~~~~~~~~~~~~~~~~~~~~~~~~

This item also controls the frequency of lease maintenance crawler runs.
The random intervals between runs have a uniform distribution with this item's value as its range.
The value is an integer number of seconds.
For example to make all intervals fall within a 7 day period::

  [storageclient.plugins.privatestorageio-zkapauthz-v2]
  lease.crawl-interval.range = 302400


lease.min-time-remaining
~~~~~~~~~~~~~~~~~~~~~~~~

This item controls the lease renewal behavior of the lease maintenance crawler.
It specifies an amount of time left on a lease.
If the crawler encounters a lease with less time left than this then it will renew the lease.
The value is an integer number of seconds.
For example to renew leases on all shares which will expire in less than one week::

  [storageclient.plugins.privatestorageio-zkapauthz-v2]
  lease.min-time-remaining = 604800

Server
------

To enable the plugin at all, add its name to the list of storage plugins in the Tahoe-LAFS configuration
(``tahoe.cfg`` in the relevant node directory)::

  [storage]
  plugins = privatestorageio-zkapauthz-v2

Then also configure the Ristretto-flavored PrivacyPass issuer the server will announce to clients::

  [storageserver.plugins.privatestorageio-zkapauthz-v2]
  ristretto-issuer-root-url = https://issuer.example.invalid/

The value of a single pass in the system can be configured here as well::

  [storageserver.plugins.privatestorageio-zkapauthz-v2]
  pass-value = 1048576

If no ``pass-value`` is given then a default will be used.
The value given here must agree with the value clients use in their configuration or the storage service will be unusable.

The storage server must also be configured with the path to the Ristretto-flavored PrivacyPass signing key.
To avoid placing secret material in tahoe.cfg,
this configuration is done using a path::

  [storageserver.plugins.privatestorageio-zkapauthz-v2]
  ristretto-signing-key-path = /path/to/signing.key

The signing key is the keystone secret to the entire system and must be managed with extreme care to prevent unintended disclosure.
If things go well a future version of ZKAPAuthorizer will remove the requirement that the signing key be distributed to storage servers.
