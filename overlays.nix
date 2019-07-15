self: super: {
  python = super.python.override {
    packageOverrides = python-self: python-super: {
      # new tahoe-lafs dependency
      eliot = pkgs.pythonPackages.callPackage ./eliot.nix { };
      # new autobahn requires a newer cryptography
      cryptography = pkgs.pythonPackages.callPackage ./cryptography.nix { };
      # new tahoe-lafs depends on a very recent autobahn for better
      # websocket testing features.
      autobahn = pkgs.pythonPackages.callPackage ./autobahn.nix { };

      # tahoe-lafs in nixpkgs is packaged as an application!  so we have to
      # re-package it ourselves as a library.
      tahoe-lafs = pkgs.pythonPackages.callPackage ./tahoe-lafs.nix { };
    };
  };
}
