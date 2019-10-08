Configuration
=============

Client
------

To enable the plugin at all, add its name to the list of storage plugins in the Tahoe-LAFS configuration
(``tahoe.cfg`` in the relevant node directory)::

  [client]
  storage.plugins = privatestorageio-zkapauthz-v1

Then configure the plugin as desired in the ``storageclient.plugins.privatestorageio-zkapauthz-v1`` section.

redeemer
~~~~~~~~

This item configures the voucher redeemer the client will use to redeem vouchers submitted to it.
The ``dummy`` value is useful for testing purposes only.

For example::

  [storageclient.plugins.privatestorageio-zkapauthz-v1]
  redeemer = dummy

A value of ``ristretto`` causes the client to speak Ristretto-flavored PrivacyPass to an issuer server.
In this case, the ``ristretto-issuer-root-url`` item is also required.

For example::

  [storageclient.plugins.privatestorageio-zkapauthz-v1]
  redeemer = ristretto
  ristretto-issuer-root-url = https://issuer.example.invalid/

Note that ``ristretto-issuer-root-url`` must agree with whichever storage servers the client will be configured to interact with.
If the values are not the same, the client will decline to use the storage servers.

Server
------

To enable the plugin at all, add its name to the list of storage plugins in the Tahoe-LAFS configuration
(``tahoe.cfg`` in the relevant node directory)::

  [storage]
  plugins = privatestorageio-zkapauthz-v1

Then also configure the Ristretto-flavored PrivacyPass issuer the server will announce to clients::

  [storageserver.plugins.privatestorageio-zkapauthz-v1]
  ristretto-issuer-root-url = https://issuer.example.invalid/

The storage server must also be configured with the path to the Ristretto-flavored PrivacyPass signing key.
To avoid placing secret material in tahoe.cfg,
this configuration is done using a path::

  [storageserver.plugins.privatestorageio-zkapauthz-v1]
  ristretto-signing-key-path = /path/to/signing.key

The signing key is the keystone secret to the entire system and must be managed with extreme care to prevent unintended disclosure.
