.. Heading order = - ~ `

ZKAP Database Replication / Recovery
====================================

**Contacts:** Jean-Paul Calderone

This is a design for a system in which the client-side ZKAPAuthorizer plugin continuously maintains a remote replica of its own internal state.
These replicas are stored on storage servers reachable by the Tahoe-LAFS client node into which ZKAPAuthorizer is loaded.
These replicas can be used to recreate that database in the event primary storage of that database is lost.

Rationale
---------

The internal client-side ZKAPAuthorizer database is used to store information that is valuable to its owner.
This includes secrets necessary to construct ZKAPs.
It may also include unredeemed or partially redeemed vouchers and information about problems spending some ZKAPs.

This database is the canonical storage for this information.
That is,
if it is lost then it is not likely that it will be possible to recreate it.

A premise of ZKAPAuthorizer is that the user of the system will value storage-time
(a scarce resource to the operator of a Tahoe-LAFS storage grid).
ZKAPAuthorizer facilitates the exchange of storage-time for ZKAPs
(a scarce resource to the user of the system).
It follows that the user will value ZKAPs and their unnecessary loss should be avoided.

After the system described here is delivered to users it will be possible for users to recover all of the valuable information in the ZKAPAuthorizer database.
This is true even if the entire system holding that database is lost,
*as long as* the user has executed a basic replication setup workflow at least one time.

User Stories
------------

Recovery
~~~~~~~~

**Category:** must

As a user of ZKAPs who has lost the original device on which I installed Tahoe-LAFS with ZKAPAuthorizer
I want to be able a install a new instance of Tahoe-LAFS with ZKAPAuthorizer to recover all of my ZKAPs
so that I can use all of the storage that I paid for before I lost my device.

**Acceptance Criteria:**

  * 100% of storage-time which was paid for at the time of the loss is recovered
  * Recovery is not impacted by the exact time of the failure that prompts it.
  * The recovery workflow is integrated into the backup/recovery workflow for all other grid-related secrets.

    * In particular, no extra user-facing steps are required for ZKAP or voucher recovery.

  * Only the holder of the recovery key can recover the storage-time.
  * Wallclock time to complete recovery is not increased.
  * At least 500 GiB-months of unused storage-time can be recovered.
  * At least 50 GiB-months of error-state ZKAPs can be recovered.
  * At least 100 vouchers can be recovered.
  * Recovery using ZKAPAuthorizer with schema version N can be performed with a replica at schema version <= N.

Backed Up Value
~~~~~~~~~~~~~~~

**Category:** must

As a user of ZKAPs
I want newly purchased ZKAPs to be backed up automatically
so that I can use the system without always worrying about whether I have protected my investment in the system.

**Acceptance Criteria:**

  * All of the recovery criteria can be satisfied.
  * The replication workflow is integrated into the backup/recovery workflow for all other grid-related secrets.

    * In particular, no extra steps are required for ZKAP or voucher replication.

  * Changes to a database at schema version N can be backed up even when the replica contains state from schema version <= N.

*Gather Feedback*
-----------------

*It might be a good idea to stop at this point & get feedback to make sure you're solving the right problem.*

Alternatives Considered
-----------------------

Juggle Tokens
~~~~~~~~~~~~~

ZKAPAuthorizer currently exposes an HTTP API for reading and writing the list of token signatures.
A third party can periodically read and back up this list.
On recovery it can write the last back into ZKAPAuthorizer.

This has the downside that it requires a third party to keep up-to-date with ZKAPAuthorizer's internal schema:

* This mechanism never accounted for the ``vouchers`` table.
* This mechanism was not updated for the ``invalid-unblinded-tokens`` or ``redemption-groups`` tables.

Consequently ZKAPAuthorizer now has internal state that cannot be backed up by any third party.
The mechanism could be updated to account for these changes but only at the cost of an increase in its complexity.
Any future schema changes will also need to be designed so they can also be integrated into this system.

In this system each kind of application-level state needs dedicated application-level integration with the replication scheme.
Therefore the complexity of the system scales at least linearly with the number of kinds of application-level state.
The complexity of this scheme scales at least linearly with the number of schema changes in ZKAPAuthorizer because
Overall complexity is further increased by the fact that schema changes also need to be accounted for.

Database Copying
~~~~~~~~~~~~~~~~

All of the internal state resides in a single SQLite3 database.
This file can be copied to the on-grid storage location.
This requires a ZKAPAuthorizer API to suspend writes to the database so a consistent copy can be made.
The replica must be kept fresh for two reasons:

* When a new voucher is funded or redeemed for new ZKAPs there is new value present in the database that is not present in an old copy of it.
* As ZKAPs in the replica are spent by the client the cost to discard these after recovery grows.

To keep the replica fresh multiple complete copies of the database need to be uploaded.

This requires a large amount of bandwidth to upload full copies of the database periodically.
The database occupies about 5 MiB per 10,000 ZKAPs.

Copying "Sessions"
~~~~~~~~~~~~~~~~~~

SQLite3 has a "session" system which can be used to capture all changes made to a database.
All changes could be captured this way and then uploaded to the on-grid storage location.
The set of changes will be smaller than new copies of the database and save on bandwidth and storage.

The Python bindings to the SQLite3 library are missing support for the session-related APIs.
It's also not possible to guarantee that all changes are always captured.
This may allow the base database state and the session logs to become difficult to reconcile automatically.

Copying WAL
~~~~~~~~~~~

SQLite3 has a (W)rite (A)head (L)og mode where it writes out all database changes to a "WAL" file before committing them.
All changes could be captured this way and then uploaded to the on-grid storage location.
The set of files will be smaller than new copies of the database and save on bandwidth and storage.

This idea is implemented by https://litestream.io/ as a stand-alone process which supports an SFTP server as a backend.
This conveniently deals with the sometimes subtle task of noticing exactly which parts of the WAL file need to be replicated.
It also operates entirely as an orthogonal service so that no directly replication-related changes need to be encoded into the ZKAPAuthorizer application logic.
To get data onto the grid the Tahoe-LAFS client node can operate as an SFTP server for Litestream to talk to
(though ours currently does not).

Litestream is implemented in Golang which is not the team's favorite language
(mainly relevant only if we need to do any debugging or development on Litestream itself).
The Litestream executable is 22MB stripped and will need to be build for all three supported platforms.
Twisted's SFTP server is not extremely well maintained and Tahoe's application-specific instantiation of it is particularly weird.
Even though Litestream provides replication services orthogonally our code will still need to be expanded with:

* a process management system to start and stop Litestream at the right times
* configuration generation for Litestream
* Tahoe-LAFS SFTP server configuration generation
* build and packaging complexity

Litestream prefers to write many small files.
This is generally a reasonable preference but it interacts poorly with our pricing model.
This can probably be mitigated somewhat with a carefully constructed configuration but probably cannot be fixed optimally without changes in Litestream itself.

Application-Specific Change Journal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ZKAPAuthorizer itself could write a log in an application-specific format recording all changes it makes to the database.
This log could be uploaded to the on-grid storage-location location or executed against data stored there.
This log will be smaller than new copies of the database and save on bandwidth and storage.

This involves non-trivial implementation work in ZKAPAuthorizer to capture all changes and record them in such a log.
It also requires logic to play back the log to recover the state it represents.
It may also be sensitive to changes made outside of the control of the ZKAPAuthorizer implementation -
though with enough effort it can be made less sensitive than the other log playback based approaches.

This has almost all of the complexity of ``Application SQL Log`` but little or none of its generality.

Application SQL Log
~~~~~~~~~~~~~~~~~~~

ZKAPAuthorizer itself could write a log of all SQL it executes against the SQLite3 database.
This log could be uploaded to the on-grid storage location.
This log will be smaller than new copies of the database and save on bandwidth and storage.

This involves some implementation work in ZKAPAuthorizer to capture the stream of SQL statements
(including values of parameters).
It is likely to be sensitive to changes made outside of the control of the ZKAPAuthorizer implementation -
though less sensitive than the WAL-based approach.

The implementation work is rather contained due to the factoring of our database access.
By implementing this ourselves we can use the best possible Tahoe-LAFS APIs and storage representation.

Binary Deltas
~~~~~~~~~~~~~

An additional copy of the SQLite3 database could be kept around against which binary diffs could be computed.
This additional copy could be copied to the on-grid storage location and would quickly become outdated.
As changes are made to the working copy of the database local copies could be made and diffed against the additional copy.
These binary diffs could be copied to the on-grid storage location and would update the copy already present.
These diffs would be smaller than new copies of the database and save on bandwidth and storage.
At any point if the diffs grow too large the process can be started over with a new, recent copy of the database.

Text Deltas
~~~~~~~~~~~

The full contents of a SLQite3 database can be dumped as SQL text at any time.
The *Binary Deltas* design could be applied to these SQL text dumps instead.
Text diffs could be compressed to reduce the overhead compared to binary deltas.
These diffs are likely to be slightly easier to work with in the event any problems arise.

Comparison & Decision
---------------------

This table shows rankings for each implementation option.
Rankings are broken down along a number of different dimensions.
Options are ranked with respect to each other
(ties are allowed).
Higher rankings reflect more preferred behavior.
Since no option has been implemented all rankings are estimates.

+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|             |Juggle  |Database|Copying  |Copying |App-Specific  |App SQL |Binary  |Text    |
|             |Tokens  |Copying |Sessions |WAL     |Change Journal|Log     |Delta   |Delta   |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|Storage Cost |7       |0       |6        |6       |6             |3       |2       |1       |
|[11]_        |        |        |         |        |              |        |        |        |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|Network Cost |7       |0       |6        |6       |6             |3       |2       |1       |
|[12]_        |        |        |         |        |              |        |        |        |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|Replica      |7       |0       |5        |5       |7             |5       |2       |2       |
|Freshness    |        |        |         |        |              |        |        |        |
|[13]_        |        |        |         |        |              |        |        |        |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|CPU Cost     |7       |0       |5        |5       |7             |5       |2       |2       |
|[14]_        |        |        |         |        |              |        |        |        |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|Software     |3       |7       |0        |1       |3             |6       |6       |6       |
|Complexity   |        |        |         |        |              |        |        |        |
|[15]_        |        |        |         |        |              |        |        |        |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|Maintenance  |1       |7       |3        |3       |1             |7       |7       |7       |
|Cost [17]_   |        |        |         |        |              |        |        |        |
|             |        |        |         |        |              |        |        |        |
|             |        |        |         |        |              |        |        |        |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|Packaging /  |7       |7       |0        |2       |7             |7       |2       |7       |
|Distribution |        |        |         |        |              |        |        |        |
|Complexity   |        |        |         |        |              |        |        |        |
|[16]_        |        |        |         |        |              |        |        |        |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+
|Total        |39      |21      |25       |28      |37            |36      |23      |26      |
+-------------+--------+--------+---------+--------+--------------+--------+--------+--------+

By raw score the overall ranking is:

#. Juggle Tokens (39)
#. App-Specific Change Journal (37)
#. Application SQL Log (36)
#. Copying WAL (28)
#. Copying Sessions (25)
#. Text Delta (26)
#. Binary Delta (23)
#. Database Copying (21)

The top three options are closely ranked.
**App SQL Log** scores better than the first- and second-ranked option on "software complexity" and "maintenance cost".
This means the initial implementation is more likely to be successful and it is less likely to cause future development problems.
Therefore **App SQL Log** is the chosen design.

Detailed Implementation Design
------------------------------
*Focus on:*

* external and internal interfaces
* how externally-triggered system events (e.g. sudden reboot; network congestion) will affect the system
* scalability and performance

State
~~~~~

A replica consists of the following pieces of state:

#. a snapshot

   A snapshot the minimal sequence of SQL statements
   (with arguments embedded)
   which will re-create the database from which it was created [10]_.
   A snapshot can be produced using the ``iterdump`` feature of the Python SQLite3 module.

#. an event stream

   An event stream is a sequence of SQL statements
   (with arguments embedded)
   which update a certain database snapshot.
   Each statements in the event stream is paired with a sequence number.
   Sequence numbers are assigned in a monotonically increasing sequence that corresponds to the order in which the statements were executed.
   These can be used to address a specific statement within the event stream.

#. a sequence number

   A snapshot includes state which was created by statements from some prefix of the event stream.
   The snapshot is paired with a sequence number indicating the last statement in this prefix.
   This allows recovery to find the correct position in the event stream to begin replaying statements to reconstruct the newest version of the database.

The event stream is represented in the local database in a new table::

  CREATE TABLE [event-stream] (
      -- A sequence number which allows us to identify specific positions in
      -- the sequence of modifications which were made to the database.
      [sequence-number] INTEGER PRIMARY KEY,

      -- A SQL statement which likely made a change to the database state.
      [statement] TEXT,
  );

Arguments are substituted into the statement so that they match the form of statements generated during the *snapshot* phase.

Replication
~~~~~~~~~~~

The replication process is as follows:

#. Replication is configured using the external interface.

   #. The *replica directory*,
      a new mutable directory,
      is created on grid.
   #. The write capability is added to the database.
   #. The read capability is returned to the external caller.

#. If there is not a sufficiently up-to-date snapshot [1]_ on the grid then one is created [7]_ in the *replica directory*.
   Any obsolete snapshots [2]_ in the *replica directory* are pruned.

#. As the application runs the event stream is recorded [3]_ locally in the database.

#. If the event stream in the database is large enough [4]_ or the application triggers an event stream flush [5]_ then:

   #. it is added to the event stream in the *replica directory* [6]_
   #. statements which were added are pruned from the database [8]_

#. If an event stream object in the *replica directory* contains only statements that are already part of the snapshot those statements are pruned. [9]_

All uploads inherit the redundancy configuration from the Tahoe-LAFS client node.

Recovery
~~~~~~~~

The recovery process is as follows:

#. An empty database is created.
#. The snapshot is downloaded.
#. The event stream is downloaded.
#. The statements from the snapshot are executed against the database.
#. The statements from the event stream,
   starting at the first statement after the snapshot's sequence number,
   are executed against the database.

External Interfaces
-------------------

Specification
~~~~~~~~~~~~~

See the `OpenAPI specification <backup-recovery-openapi.html>`_.

Sample Sessions
~~~~~~~~~~~~~~~

The expected interaction pattern involves two API calls.

#. Early in the Tahoe-LAFS client node setup/configuration process,
   configure replication:

   .. code-block:: html

      POST /storage-plugins/privatestorageio-zkapauthz-v1/replicate

      201 Created
      Content-Type: application/json

      {"recovery-capability": "URI:DIR-RO:xxxx"}

#. Normal use of the Tahoe-LAFS client node,
   including redeeming vouchers and spending ZKAPs.

#. After losing the Tahoe-LAFS client node,
   create a new Tahoe-LAFS client node and recover from the replica:

   .. code-block:: html

      POST /storage-plugins/privatestorageio-zkapauthz-v1/recover
      Content-Type: application/json
      Content-Length: ...

      {"recovery-capability": "URI:DIR-RO:xxxx"}

      200 OK
      Content-Type: application/json

      {}

#. The new Tahoe-LAFS client node now has the same ZKAPAuthorizer state as it did prior to lose of the original instance.

Data Integrity
--------------

Schema Upgrades
~~~~~~~~~~~~~~~

A database snapshot will include schema modification statements
(DDL statements)
which completely initialize the schema for all subsequent data manipulation statements
(DML statements)
in the snapshot.

An event stream must contain information about schema modifications because different statements in the stream may require different versions of the schema.
This will happen whenever

#. a snapshot is created
#. some statements are recorded in the event stream
#. a schema upgrade is performed (e.g. as a result of client software upgrade)
#. more statements are recorded in the event stream

These requirements can be exactly satisfied if DDL and DML statements are handled uniformly.
If DDL statements are recorded in the event stream and later executed during recovery the schema will always match the requirements of the DML statements.

Automated Testing
~~~~~~~~~~~~~~~~~

The replication/recovery functionality can be implemented orthogonally to ZKAPAuthorizer application logic.
This means it can be tested orthogonally to ZKAPAuthorizer application logic.
This means the core logic should be amenable to high-quality unit testing.

Successful replication in practice depends on reads from and writes to Tahoe-LAFS storage.
Automated testing for this logic probably requires integration-style testing due to the lack of unit testing affordances from the Tahoe-LAFS project.

Runtime Health-Checks
~~~~~~~~~~~~~~~~~~~~~

The maintenace of a replica is an ongoing process.
The replica loses value,
up to and including *all* value,
if that maintenance process breaks down at some point.

Ideally it would be possible for some component to detect problems with this process.
Where possible,
problems should be corrected automatically.
At some point the system may determine no automatic correction is possible and user intervention is required.

The design for such user interaction is out of scope for this document.

Replication/Recovery System Upgrades
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This document describes the on-grid schema for version 1 of this system.
This version information will be encoded on the grid alongside snapshots and event streams.

This will allow the version to be recognized and handled appropriately by future versions of the software which may implement a different replication/recovery system.

Conveniently,
it is always possible to create a fresh snapshot from client-side state.
This suggests a worst-case upgrade path where a new snapshot is created,
following a new schema,
after a client upgrade and the old replica is discarded.

Security
--------

Terms
~~~~~

Let the data that comes from users of the system and is uploaded to and download from the Tahoe-LAFS grid be known as *user data*.

Let the data that ZKAPAuthorizer itself creates and uses to manage payments be known as *accounting data*.

Threat Model
~~~~~~~~~~~~

This design aims to defend accounting data in the same way user data is defended.
If the capability for the replica directory is kept confidential then the accounting data will be kept confidential.
It is up to the party using the external interface to keep the capability confidential.

This system creates new copies of accounting data on the Tahoe-LAFS grid.
The convenience-related requirements for the user stories at the top of this design imply that the capabilities for accessing user data will grant access to read the accounting data replicas created by this system.
This is a strictly worse failure-mode than disclosure of either user data or accounting data separately since it potentially allows identifying information from the payment system to be linked to specific user data.
Compare:
* I know Alice has some data but I don't know what that data is.
* I know someone has dataset **X** but I don't know who.
* I know Alice has dataset **X**.

This design does not mitigate this risk.
It may be beneficial to do so in the future.

Backwards Compatibility
-----------------------

Prior to implementation of this design ZKAPAuthorizer does not maintain backups or replicas.
Third-parties which have their own backups or replicas should be able to activate the system described here and then discard their backup/replica data.

Performance and Scalability
---------------------------

Storage Requirements
~~~~~~~~~~~~~~~~~~~~

We should build a tool to measure the storage requirements of the replica system.

Network Transfers
~~~~~~~~~~~~~~~~~

We should build a tool to measure data transferred over the network for creation and maintenance of a replica.

Memory Usage
~~~~~~~~~~~~

We should build a tool to measure memory used by ZKAPAuthorizer with and without replicas enabled so we can compare the incremental cost of replicas.

CPU Usage
~~~~~~~~~

We should build a tool to measure CPU used by the replica system.

Further Reading
---------------

* https://litestream.io/

Footnotes
---------

.. [1] A snapshot is sufficiently up-to-date if the event stream is no more than ``N`` times larger than it.
       The size requirement exists because the event stream will grow without bounds but the snapshot should have a bounded size.
       By periodically re-snapshotting and re-starting the event stream the on-grid storage can be bounded as well.
       Some measurements may be required to choose a good value for ``N``.
       It may also be necessary to choose whether to prioritize efficient use of network bandwidth or on-grid storage space
       (and to what degree).
       If the snapshot does not exist then its size is treated as 0.

.. [2] A snapshot is obsolete if there is a completely uploaded snapshot with a greater sequence number.

.. [3] Application-code is supplied with a cursor which performs this capturing.
       Replication code bypasses this capturing so that statements which record the event stream are not themselves recorded.
       Recovery code bypasses this capturing so that statements to recreate the database are also not recorded.
       ``SELECT`` statements are ignored since they cannot change the database (XXX is this true?).

.. [4] The definition of "large enough" is chosen to produce efficient use of ZKAPs to pay for on-grid storage of the event stream.
       On-grid storage will consist of some number of shares depending on the Tahoe-LAFS client node's configuration.
       Efficiency of ZKAP usage will depend on ZKAPAuthorizer's ``pass-value`` configuration.
       So "large enough" is chosen so that a share will occupy most of the value of one ZKAP for one time period.
       Concretely this will be ``pass-value × 0.95 × shares.needed / shares.total``.
       The "efficiency factor" of 0.95 allows some slop in the system so that a single statement is not likely to increase the size from below the "large enough" limit to above the size component of the ``pass-value``
       (which would result in doubling the cost to store the object).
       For example,
       for a ``pass-value`` of 1MB(×month),
       a ``shares.needed`` of 3,
       and a ``shares.total`` of 5,
       "large enough" is ``1MB × 0.95 × 3 / 5`` or 540,000 bytes.
       A 570,000 byte object erasure-encodes under these parameters to 950,001 bytes.
       Therefore in this configuration 570,000 bytes is "large enough".

       If Tahoe-LAFS had better support for appending data to a mutable object we could upload more frequently and pack new data into an existing mutable until it reached an "efficient" size.
       But it does not.

.. [5] Certain database changes,
       such as insertion of a new voucher,
       are particularly valuable and should be captured as quickly as possible.
       In contrast,
       there is some tolerance for losing a database change which marks a token as spent since this state can be recreated by the application if necessary.

.. [6] The SQL statements are joined with newline separators.
       The resulting string is uploaded as a new immutable object next to the existing snapshot object.
       The sequence number of the first statement it includes is added as metadata for that object in the containing directory.

.. [7] The SQL statements from ``iterdump``,
       except for those relating to the event stream table,
       are joined with newline separators and compressed using lzma.
       The compressed blob is uploaded as an immutable object.
       The metadata of the object in the containing directory includes the snapshot's sequence number.

.. [8] The upload may proceed concurrently with further database changes.
       Of course only the uploaded statements are deleted from the local table.

.. [9] The event stream objects can be placed into an order such that the sequence of each object is less than that of the next.
       For each event stream object **E**\ :sub:`n` which has an event stream object **E**\ :sub:`m` following it in this sequence,
       if the snapshot's sequence number is greater than or equal to **E**\ :sub:`m`'s sequence number then **E**\ :sub:`n` is completely contained by the snapshot.

.. [10] Rows in the ``[event-stream]`` table are always excluded from the snapshot.
	They are not needed for recovery.
	The state they represent is always reflected elsewhere in the database.
	The DDL statements for ``[event-stream]`` *are* included.

.. [11] The cost in ZKAPs to store the replica on the grid.

.. [12] The network traffic required to create and maintain the replica.

.. [13] The distance from the replica to the local database measured by number of changes.

.. [14] The CPU cost on the client to create and maintain the replica.

.. [15] The complexity of the software development work to implement the option starting from this design document.

.. [16] The additional implementation work required to package and distribute the resulting implementation.

.. [17] The cost to maintain this option over the course of continuing ZKAPAuthorizer development.
