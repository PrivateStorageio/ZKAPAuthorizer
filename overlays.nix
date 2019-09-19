self: super: {
  openssl = self.openssl_1_1;

  ristretto = super.callPackage ./ristretto.nix { };

  python27 = super.python27.override {
    packageOverrides = python-self: python-super: {
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
    };
  };
}
