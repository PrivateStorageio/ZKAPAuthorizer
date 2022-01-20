ZKAP Database Backup / Recovery
===============================

*The goal is to do the least design we can get away with while still making a quality product.*
*Think of this as a tool to help define the problem, analyze solutions, and share results.*
*Feel free to skip sections that you don't think are relevant*
*(but say that you are doing so).*
*Delete the bits in italics*

**Contacts:** Jean-Paul Calderone
**Date:** 2021-11-08

This is a design for a system in ZKAPAuthorizer continuously maintains a remote backof of its own internal state.
These backups are made onto the storage servers the Tahoe-LAFS node into which ZKAPAuthorizer is loaded is connected to.
These backups can be used to recover that database in the event primary storage of that database is lost.

Rationale
---------

The internal ZKAPAuthorizer database is used to store information that is valuable to its owner.
This includes secrets necessary to construct ZKAPs.
It may also include unredeemed or partially redeemed vouchers and information about problems spending some ZKAPs.

This database is the canonical storage for this information.
That is,
if it is lost then it is not likely that it will be possible to recreate it.

The premise of ZKAPAuthorizer is that ZKAPs are a scarce resource.
It follows that unnecessary loss of ZKAPs is to be avoided.

After the system described here is delivered to users it will be possible for users to recover all of the valuable information in the ZKAPAuthorizer database.
This is true even if the entire system holding that database is lost,
*as long as* the user has executed a basic backup workflow at least one time.

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

    * In particular, no extra steps are required for ZKAP or voucher recovery.

  * Only the holder of the recovery key can recover the storage-time.
  * Wallclock time to complete recovery is not increased.
  * At least 500 GiB-months of unused storage-time can be recovered.
  * At least 50 GiB-months of error-state ZKAPs can be recovered.
  * At least 100 vouchers can be recovered.
  * Recovery using ZKAPAuthorizer with schema version N can be performed with a backup at schema version <= N.

Backed Up ZKAPs
~~~~~~~~~~~~~~~

**Category:** must

As a user of ZKAPs
I want newly purchased ZKAPs to be backed up automatically
so that I can use the system without always worrying about whether I have protected my investment in the system.

**Acceptance Criteria:**

  * All of the recovery criteria can be satisfied.
  * The backup workflow is integrated into the backup/recovery workflow for all other grid-related secrets.

    * In particular, no extra steps are required for ZKAP or voucher backup.

  * Changes to a database at schema version N can be backed up even when the backup contains state from schema version <= N.

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

This has the downside that it requires a third party to keep up-to-date with ZKAPAuthorizer's internal schema.
This has not happened in practice and ZKAPAuthorizer now has more internal state than is backed up by any third party.

Database Copying
~~~~~~~~~~~~~~~~

All of the internal state resides in a single SQLite3 database.
This file can be copied to the backup location.
This requires a ZKAPAuthorizer API to suspend writes to the database so a consistent copy can be made.

This requires a large amount of bandwidth to upload full copies of the database periodically.
The database occupies about 5 MiB per 10,000 ZKAPs.

Copying "Sessions"
~~~~~~~~~~~~~~~~~

SQLite3 has a "session" system which can be used to capture all changes made to a database.
All changes could be captured this way and then uploaded to the backup location.
The set of changes will be smaller than new copies of the database and save on bandwidth and storage.

The Python bindings to the SQLite3 library are missing support for the session-related APIs.
It's also not possible to guarantee that all changes are always captured.
This may allow the base database state and the session logs to become difficult to reconcile automatically.

Copying WAL
~~~~~~~~~~~

SQLite3 has a (W)rite (A)head (L)og mode where it writes out all database changes to a "WAL" file before committing them.
All changes could be captured this way and then uploaded to the backup location.
The set of files will be smaller than new copies of the database and save on bandwidth and storage.

This requires making sure to use the database in the correct mode.
It is likely also sensitive to changes made outside of the control of the ZKAPAuthorizer implementation.

Application-Specific Change Journal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ZKAPAuthorizer itself could write a log in an application-specific format recording all changes it makes to the database.
This log could be uploaded to the backup location or executed against data stored in the backup location.
This log will be smaller than new copies of the database and save on bandwidth and storage.

This involves non-trivial implementation work in ZKAPAuthorizer to capture all changes and record them in such a log.
It also requires logic to play back the log to recover the state it represents.
It may also be sensitive to changes made outside of the control of the ZKAPAuthorizer implementation -
though with enough effort it can be made less sensitive than the other log playback based approaches.

Application SQL Log
~~~~~~~~~~~~~~~~~~~

ZKAPAuthorizer itself could write a log of all SQL it executes against the SQLite3 database.
This log could be uploaded to the backup location.
This log will be smaller than new copies of the database and save on bandwidth and storage.

This involves non-trivial implementation work in ZKAPAuthorizer to capture the stream of SQL statements
(including values of parameters).
It is likely also sensitive to changes made outside of the control of the ZKAPAuthorizer implementation -
though less sensitive than the WAL-based approach.

Binary Deltas
~~~~~~~~~~~~~

An additional copy of the SQLite3 database could be kept around against which binary diffs could be computed.
This additional copy could be copied to the backup location and would quickly become outdated.
As changes are made to the working copy of the database local copies could be made and diffed against the additional copy.
These binary diffs could be copied to the backup location and would update the copy already present.
These diffs would be smaller than new copies of the database and save on bandwidth and storage.
At any point if the diffs grow to large the process can be started over with a new, recent copy of the database.

Text Deltas
~~~~~~~~~~~

The full contents of a SLQite3 database can be dumped as SQL text at any time.
The *Binary Deltas* design could be applied to these SQL text dumps instead.
Text diffs could be compressed to reduce the overhead compared to binary deltas.
These diffs are likely to be slightly easier to work with in the event any problems arise.

*What we've considered.*
*What trade-offs are involved with each choice.*
*Why we've chosen the one we did.*

Detailed Implementation Design
------------------------------

*Focus on:*

* external and internal interfaces
* how externally-triggered system events (e.g. sudden reboot; network congestion) will affect the system
* scalability and performance

Summary
~~~~~~~



External Interfaces
~~~~~~~~~~~~~~~~~~~



Data Integrity
~~~~~~~~~~~~~~

*If we get this wrong once, we lose forever.*
*What data does the system need to operate on?*
*How will old data be upgraded to meet the requirements of the design?*
*How will data be upgraded to future versions of the implementation?*

Security
~~~~~~~~

*What threat model does this design take into account?*
*What new attack surfaces are added by this design?*
*What defenses are deployed with the implementation to keep those surfaces safe?*

Backwards Compatibility
~~~~~~~~~~~~~~~~~~~~~~~

*What existing systems are impacted by these changes?*
*How does the design ensure they will continue to work?*

Performance and Scalability
~~~~~~~~~~~~~~~~~~~~~~~~~~~

*How will performance of the implementation be measured?*

*After measuring it, record the results here.*

Further Reading
---------------

*Links to related things.*
*Other designs, tickets, epics, mailing list threads, etc.*
