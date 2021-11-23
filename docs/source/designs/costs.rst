Costs
=====

ZKAPAuthorizer defines costs for certain Tahoe-LAFS storage operations.
It overlays its own protocol on the Tahoe-LAFS storage protocol which accepts ZKAPs as payments along with these operations.
The underlying storage operations are only allowed when the supplied payment covers the cost.

Storage-Time
============

Storage servers incur a storage cost over time to provide service to storage clients.
A storage server must hold ciphertext from the time it is uploaded until the last time a client needs to download it.

The unit of cost ZKAPAuthorizer imposes is storage × time.
The currency used by ZKAPAuthorizer is a (Z)ero (K)nowledge (A)ccess (P)ass -- a ZKAP.
If a ZKAP is worth 1 MB × 1 month (configurable per-grid) then a client must spend 1 ZKAP to store up to 1 MB for up to 1 month.
To store up to 1 MB for up to 2 months a client spends 2 ZKAPs.
To store up to 2 MB for up to 1 month a client spends 2 ZKAPs.

A ZKAP is the smallest unit of the currency.
When sizes or times do not fall on integer multiples of 1 MB or 1 month the cost is rounded up.

Leases
------

The period of time a Tahoe-LAFS storage server promises to retain a share is controlled by "leases".
A lease has an expiration time after which it is no longer effective.
A lease is associated with a single share.
As long as at least one lease has not expired a storage server will keep that share.
Clients are required to periodically "renew" leases for shares they wish the server to keep.

The length of a lease (1 month) provides the "time" component of storage-time.

Here are some examples:

* renewing the lease on a 100 KB share costs 1 ZKAP
* renewing the lease on a 1 MB share costs 1 ZKAP
* renewing the lease on a 1.5 MB share costs 2 ZKAPs
* renewing the lease on a 10 MB share costs 10 ZKAPs

Renewing a lease sets the expiration time to be 1 month after the time of the operation.

Shares
------

Tahoe-LAFS storage servers accept "shares" for storage.
Immutable data is represented as shares in "buckets".
Mutable data is represented as shares in "slots".
All shares in the same bucket (or slot) relate to the same "file".

The size of a share provides the "storage" component of storage-time.

Immutable Data
~~~~~~~~~~~~~~

The original Tahoe-LAFS storage protocol automatically adds a lease to all immutable shares it receives at the time the upload completes.
It also automatically renews leases on all shares in the same bucket as the newly uploaded share.

When ZKAPAuthorizer is used newly uploaded immutable shares still have a lease added to them.
The behavior of renewing leases on all other shares in the same bucket is disabled.

The cost of uploading an immutable share is the size of the share times the duration of a lease.
Here are some examples:

* a 100 KB share costs 1 ZKAP to upload
* a 1 MB share costs 1 ZKAP to upload
* a 1.5 MB share costs 2 ZKAPs to upload
* a 10 MB share costs 10 ZKAPs to upload

Mutable Data
~~~~~~~~~~~~

The original Tahoe-LAFS storage protocol automatically renews leases on mutable shares when they are first created and whenever they are changed.

When ZKAPAuthorizer is used newly uploaded mutable shares still have a lease added to them.
The behavior of renewing leases on all changed shares is disabled.

The cost of creating a mutable share is the size of the share times the duration of a lease.
This is exactly the same method as is used to compute the cost of uploading an immutable share.

The cost of modifying a mutable share is based on the change in size that results:
the cost of the share before the change is subtracted from the cost of the share after the change.
If the cost is negative it is considered to be zero.

Here are some examples:

* creating a 100 KB share costs 1 ZKAP
* extending a 100 KB share to 200 KB is free
* extending a 1 MB share to 1.5 MB costs 1 ZKAP
* extending a 1.5 MB share to 2 MB is free
* extending a 2 MB share to 10 MB costs 8 ZKAPs
* truncating a 10 MB share to 2 MB is free
* rewriting the contents of a 5 MB share without changing its length is free

Note that leases are *not* renewed when a mutable share is modified.
When the modification has a positive cost this results in the client being overcharged.
The amount of the overcharge is a function of three variables:

* The **lease period** currently fixed at 31 days.
* The **remaining lease time** which is the difference between the time when the current lease expires and the time of the operation.
* The **price increase** which is the number of ZKAPs the modification costs.

The amount of the overcharge is **lease period remaining** / **lease period** × **price increase**.
See <https://github.com/PrivateStorageio/ZKAPAuthorizer/issues/254> for efforts to remedy this.
