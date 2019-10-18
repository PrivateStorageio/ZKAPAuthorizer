self: super: {
  ristretto = super.callPackage ./ristretto.nix { };

  python27 = super.python27.override {
    packageOverrides = python-self: python-super: {
      # The newest typing is incompatible with the packaged version of
      # Hypothesis.  Upgrading Hypothesis is like pulling on a loose thread in
      # a sweater.  I pulled it as far as pytest where I found there was no
      # upgrade route because pytest has dropped Python 2 support.
      # Fortunately, downgrading typing ends up being fairly straightforward.
      #
      # For now.  This is, no doubt, a sign of things to come for the Python 2
      # ecosystem - the early stages of a slow, painful death by the thousand
      # cuts of incompatibilities between libraries with no maintained Python
      # 2 support.
      typing = python-self.callPackage ./typing.nix { };

      # new tahoe-lafs dependency
      eliot = python-self.callPackage ./eliot.nix { };

      # tahoe-lafs in nixpkgs is packaged as an application!  so we have to
      # re-package it ourselves as a library.
      tahoe-lafs = python-self.callPackage ./tahoe-lafs.nix { };

      # we depend on the privacypass python library, a set of bindings to the
      # challenge-bypass-ristretto Rust library
      privacypass = python-self.callPackage ./privacypass.nix { };

      # And add ourselves to the collection too.
      zkapauthorizer = python-self.callPackage ./zkapauthorizer.nix { };
    };
  };
}
