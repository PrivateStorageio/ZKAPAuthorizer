ZKAP Database Backup / Recovery
===============================

*The goal is to do the least design we can get away with while still making a quality product.*
*Think of this as a tool to help define the problem, analyze solutions, and share results.*
*Feel free to skip sections that you don't think are relevant*
*(but say that you are doing so).*
*Delete the bits in italics*

**Contacts:** Jean-Paul Calderone
**Date:** 2021-11-08

This is a design for a system in which *another component* can perform consistent backups of the internal ZKAPAuthorizer database which can be used to recover that database in the event primary storage of that database is lost.
The system does *not* allow ZKAPAuthorizer to maintain backups *on its own*.

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

*Gather Feedback*
-----------------

*It might be a good idea to stop at this point & get feedback to make sure you're solving the right problem.*

Alternatives Considered
-----------------------

*What we've considered.*
*What trade-offs are involved with each choice.*
*Why we've chosen the one we did.*

Detailed Implementation Design
------------------------------

*Focus on:*

* external and internal interfaces
* how externally-triggered system events (e.g. sudden reboot; network congestion) will affect the system
* scalability and performance

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
