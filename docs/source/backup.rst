ZKAP Backup/Restore
===================

A large part of the intended purpose of ZKAPs is to allow a value exchange between storage provider and storage consumer.
As such the ZKAPs themselves represent some value.
Thus it is to be expected that users will want that value safe-guarded.
One way to do this is for the internal state of ZKAPAuthorizer to be backed up periodically.

Overview
--------

ZKAPAuthorizer's internal state can be backed up and restored by backing up and restoring a SQLite3 database it maintains.
After a backup has been taken it is possible to update a small "checkpoint" that keeps track of spent ZKAPs.
This makes it relatively efficient to keep a backup up-to-date with respect to spending operations.
Whenever a new voucher is purchased a new complete backup must be made to capture the associated new state.

Backup
------

The Database
~~~~~~~~~~~~

ZKAPAuthorizer keeps all of its internal state in a SQLite3 database.
This database is kept in the private directory of the Tahoe-LAFS node into which the plugin is installed.
The database filename is ``privatestorageio-zkapauthz-v1.sqlite3``.
For example,
for a Tahoe-LAFS node that keeps it state at ``~/.tahoe``,
the ZKAPAuthorizer database can be found at ``~/.tahoe/private/privatestorageio-zkapauthz-v1.sqlite3``.

The existence of the databaes file is consider part of ZKAPAuthorizer's public interface.
The fact that all of ZKAPAuthorizer's internal state is stored in this database is considered part of the public interface as well.

The exact schema and contents of this database are *not* considered part of the public interface.
Third-parties should feel free to back up this database file
(following SQLite3-recommended practices)
and restore it as necessary to recover using this backup.
Third-parties should not make any other assumptions about the file
(such as that it has a particular schema).

The Checkpoint
~~~~~~~~~~~~~~

ZKAPAuthorizer spends ZKAPs in a deterministic order.
This means if the next ZKAP to be spent is known then it is possible to separate all other ZKAPs into "already spent" and "not spent" groups.
ZKAPAuthorizer exposes the next ZKAP to be spent like this::

  GET /storage-plugins/privatestorageio-zkapauthz-v1/unblinded-token?limit=1

The checkpoint is the first element of the ``unblinded-tokens`` property of the response.

See :file:interface.rst for details.

Third-parties should periodically get this value and update the backup with it.

Restore
-------

The Database
~~~~~~~~~~~~

It is sufficient to copy the backed up database file into the correct location.
This is the same location from which it was originally copied,
relative to the Tahoe-LAFS node directory.

This must be done while the Tahoe-LAFS node is not running.
It may be done prior to the first run.

The Checkpoint
~~~~~~~~~~~~~~

After the Tahoe-LAFS node is started the checkpoint can be used to discard the "already spent" ZKAPs from the database::

  PATCH /storage-plugins/privatestorageio-zkapauthz-v1/unblinded-token
  Content-Type: application/json

  { "first-unspent": <checkpoint> }

This shortens the time it takes for the node to complete the recovery process proportionally to the number of "already spent" ZKAPs are being discarded.
