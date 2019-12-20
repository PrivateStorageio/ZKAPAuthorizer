Leases
======

Leases held on shares are treated as a guarantee that a storage server will hold those shares for the duration of the lease.
Leases have an expiration date which can be changed with a renewal operation to a date at a fixed distance in the future of the renewal.
Lease renewal requires the expenditure of ZKAPs in proportion to the size of the shares and the distance to the new expiration date.
Because lease the expiration date is advanced from the time of the renewal and not the time of the original expiration,
care is taken to only renew leases for which the expiration time will soon arrive.

Design
------

The process of checking leases and renewing is automated in the client storage plugin.
The storage plugin interface is not ideally shaped to support this functionality.
The following designs have been considered.

Option A
~~~~~~~~

Each ZKAPAuthorizerStorageClient is a service which is a child of the client node.
Each creates its own service child using lease_maintenance_service().
This results in linear factor of redundant lease maintenance work (equal to number of storage servers).
Requires change to Tahoe-LAFS to add clients as service children.

Option B
~~~~~~~~

Each ZKAPAuthorizerStorageClient is a service which is a child of the client node.
Each creates its own service child using lease_maintenance_service().
Lease maintenance function is augmented with a check against all other lease maintenance services.
Only the arbitrary-sort-key-smallest service ever actually runs.
This results in small-k linear factor overhead (on number of storage servers) to choose a winner but no lease maintenance overhead.
Requires change to Tahoe-LAFS to add clients as service children.

Option C
~~~~~~~~

The plugin interface has a method to create a service which is a child of the client node.
The service is the lease maintenance service as created by lease_maintenance_service().
There is only one so there is no winner-selection overhead or redundant lease maintenance work.
Requires change to Tahoe-LAFS to call new method to get service and add result as service child.

Option D
~~~~~~~~

The plugin creates and starts a single lease maintenance service itself.
The plugin reaches deep into the guts of something to find a client node so it can initialize the lease maintenance service
(an expression liked ``get_rref.im_self._on_status_changed.watchers[0].__closure__[0].cell_contents`` was considered to reach the ``StorageFarmBroker`` which is a child of ``_Client``).
The plugin glues it into the reactor itself for shutdown notification.
There is only one service so no winner-selection or redundant lease maintenance work is required.
This can be improved to Option C at some point.

On closer inspection, even the complex expression above is not sufficient to reach the correct object.
Even if a similar expression is found which works,
this option is likely more complex and fragile than *Option E*.

Option E
~~~~~~~~
The plugin creates and starts a single lease maintenance service itself.
The plugin monkey-patches ``allmydata.client._Client`` to perform initialization of the service at an appropriate time.
There is only one service so no winner-selection or redundant lease maintenance work is required.
This can be improved to Option C at some point.

Implementation
--------------

*Option E* is currently implemented.
Monkey-patching is performed at import time by ``_zkapauthorizer._plugin``.
