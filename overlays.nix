self: super: {
  openssl = self.openssl_1_1;

  ristretto = super.callPackage ./ristretto.nix { };

  python27 = super.python27.override {
    packageOverrides = python-self: python-super: {
      # # A newer version of Hypothesis is required for compatibility with the
      # # typing module which gets pulled in by some dependency or other.
      # #
      # # A bug report filed against nixpkgs -
      # # https://github.com/NixOS/nixpkgs/issues/70431
      # hypothesis = python-super.callPackage ./hypothesis.nix { };

      # # The newer hypothesis requires a newer attrs.
      # attrs = python-super.callPackage ./attrs.nix { };

      # # The newer hypothesis or attrs breaks the pytest test suite.
      # pytest = python-super.callPackage ./pytest.nix { };

      typing = python-super.callPackage ./typing.nix { };

      # new tahoe-lafs dependency
      eliot = python-super.callPackage ./eliot.nix { };
      # new autobahn requires a newer cryptography
      cryptography = python-super.callPackage ./cryptography.nix { };
      # new cryptography requires a newer cryptography_vectors
      cryptography_vectors = python-super.callPackage ./cryptography_vectors.nix { };
      # new tahoe-lafs depends on a very recent autobahn for better
      # websocket testing features.
      autobahn = python-super.callPackage ./autobahn.nix { };

      # tahoe-lafs in nixpkgs is packaged as an application!  so we have to
      # re-package it ourselves as a library.
      tahoe-lafs = python-super.callPackage ./tahoe-lafs.nix { };

      # we depend on the privacypass python library, a set of bindings to the
      # challenge-bypass-ristretto Rust library
      privacypass = python-super.callPackage ./privacypass.nix { };

      # And add ourselves to the collection too.
      zkapauthorizer = python-super.callPackage ./zkapauthorizer.nix { };
    };
  };
}
