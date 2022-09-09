Contributing to ZKAPAuthorizer
==============================

Contributions are accepted in many forms.

Examples of contributions include:

* Bug reports and patch reviews
* Documentation improvements
* Code patches

File a ticket at:

https://github.com/PrivateStorageio/ZKAPAuthorizer/issues/new

ZKAPAuthorizer uses GitHub keep track of bugs, feature requests, and associated patches.

Contributions are managed using GitHub's Pull Requests.
For a PR to be accepted it needs to have:

* an associated issue
* all CI tests passing
* patch coverage of 100% as reported by codecov.io

Updating Dependencies
---------------------

Python Dependencies
...................

We use `mach-nix <https://github.com/DavHau/mach-nix/>`_ to build python packages.
It uses a snapshot of PyPI to expose python dependencies to nix,
thus our python depedencies (on nix) are automatically pinned.
To update the PyPI snapshot (and thus our python dependencies), run

.. code:: shell

   nix flake lock --update-input pypi-deps-db

tahoe-lafs
..........

ZKAPAuthorizer declares a dependency on Tahoe-LAFS with a narrow version range.
This means that Tahoe-LAFS will be installed when ZKAPAuthorizer is installed.
It also means that ZKAPAuthorizer exerts a great deal of control over the version of Tahoe-LAFS chosen.

When installing using native Python packaging mechanisms
(for example, pip)
the relevant Tahoe-LAFS dependency declaration is in ``setup.cfg``.
See the comments there about the narrow version constraint used.

Several Nix packages are available which use different versions of Tahoe-LAFS.
The version is reflected in the package name.
For example,
``zkapauthorizer-python39-tahoe_1_17_1`` has a dependency on Tahoe-LAFS 1.17.1.

There is also a ``tahoe_dev`` variation that depends on a recent version of Tahoe-LAFS ``master``.

To update to the current master@HEAD revision, run:

.. code:: shell

   nix flake lock --update-input tahoe-lafs-dev

We intend for these updates to be performed periodically.
At the moment, they must be performed manually.
It might be worthwhile to `automate this process <https://github.com/PrivateStorageio/ZKAPAuthorizer/issues/287>` in the future.

.. note::

   Since tahoe-lafs doesn't have correct version information when installed from a github archive,
   the packaging in ``nix/tahoe-versions.nix`` includes a fake version number.
   This will need to be update manually at least when the minor version of tahoe-lafs changes.

If you want to test different versions,
you can override the ``tahoe-lafs-dev`` input on the command line.

.. code:: shell

   nix build --override-input tahoe-lafs-dev /path/to/tahoe-lafs-version .#zkapauthorizer-python39-tahoe_dev

The input can also be overridden for the test packages.
