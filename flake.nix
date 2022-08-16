{
  description = "A Tahoe-LAFS storage-system plugin which authorizes storage operations based on privacy-respecting tokens.";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?ref=nixos-22.05";
    flake-utils.url = "github:numtide/flake-utils";
    pypi-deps-db = {
      flake = false;
      url = "github:DavHau/pypi-deps-db";
    };
    mach-nix-flake = {
      flake = true;
      url = "github:DavHau/mach-nix";
      inputs = {
        pypi-deps-db.follows = "pypi-deps-db";
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };

    # Sometimes it is nice to be able to test against weird versions of some
    # of our dependencies, like arbitrary git revisions or source in local
    # paths.  If we make those dependencies inputs we can override them easily
    # from the command line.
    tahoe-lafs-dev = {
      # More recent versions of Tahoe-LAFS probably provide a flake but we
      # also want to consume older versions which don't, so just treat them
      # all as non-flakes.
      flake = false;
      url = "github:tahoe-lafs/tahoe-lafs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, mach-nix-flake, tahoe-lafs-dev, ... }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system: let

      mach-nix = mach-nix-flake.lib.${system};
      pkgs = nixpkgs.legacyPackages.${system};
      lib = pkgs.lib;

      # The names of the nixpkgs Python derivations for which we will expose
      # packages.
      pyVersions = [ "python310" "python39" ];

      # The Python version of our default package.
      defaultPyVersion = builtins.head pyVersions;

      # All of the versions our Tahoe-LAFS dependency for which we will expose
      # packages.
      tahoeVersions = pkgs.python3Packages.callPackage ./nix/tahoe-versions.nix {
        inherit tahoe-lafs-dev;
      };

      # The matrix of package configurations.
      packageCoordinates = lib.attrsets.cartesianProductOfSets {
        pyVersion = pyVersions;
        tahoe-lafs = tahoeVersions;
      };

      # A formatter to construct the appropriate package name for a certain
      # configuration.
      packageName = { pyVersion, tahoe-lafs }:
        "zkapauthorizer-${pyVersion}-tahoe_${tahoe-lafs.version}";

      # The Hypothesis profiles of the test packages which we will expose.
      hypothesisProfiles = [ "fast" "ci" "big" "default" ];

      # The coverage collection options for the test packages which we will expose.
      coverageOptions = [ false true ];

      # The matrix of test configurations.
      testCoordinates = lib.attrsets.cartesianProductOfSets {
        pyVersion = pyVersions;
        tahoe-lafs = tahoeVersions;
        hypothesisProfile = hypothesisProfiles;
        collectCoverage = coverageOptions;
      };

      # A formatter to construct the appropriate derivation name for a test
      # configuration.
      testName = { pyVersion, tahoe-lafs, hypothesisProfile, collectCoverage }:
        builtins.concatStringsSep "-" [
          "tests"
          "${pyVersion}"
          "tahoe_${tahoe-lafs.version}"
          (if hypothesisProfile == null then "default" else hypothesisProfile)
          (if collectCoverage then "cov" else "nocov")
        ];

      defaultPackageName = packageName (builtins.head packageCoordinates);

      inherit (import ./nix/lib.nix {
        inherit pkgs lib mach-nix;
        src = ./.;
      }) packageForVersion testsForVersion derivationMatrix toWheel;

    in rec {
      devShells = {
        default = pkgs.mkShell {
          buildInputs = [
            # Put a Python environment that has all of the development, test,
            # and runtime dependencies in it - but not the package itself.
            (mach-nix.mkPython {
              python = defaultPyVersion;
              requirements = ''
                ${builtins.readFile ./requirements/test.in}
                ${builtins.readFile ./requirements/typecheck.in}
                ${self.packages.${system}.default.requirements}
              '';
            })
          ];

          # Add the working copy's package source to the Python environment so
          # we get a convenient way to test against local changes.  Observe
          # that the use of $PWD means this only works if you run `nix
          # develop` from the top of a source checkout.
          shellHook =
            ''
            export PYTHONPATH=$PWD/src
          '';
        };
      };

      packages =
        derivationMatrix testCoordinates testName testsForVersion //
        derivationMatrix packageCoordinates packageName packageForVersion //
        { default = self.packages.${system}.${defaultPackageName};
          wheel = toWheel self.packages.${system}.default;
        };

      apps = let
        tahoe-env = mach-nix.mkPython {
          python = defaultPyVersion;
          packagesExtra = [ self.packages.${system}.default ];
        };
        twine-env = pkgs.python310.withPackages (ps: [ ps.twine ]);
      in {
        default = { type = "app"; program = "${tahoe-env}/bin/tahoe"; };
        twine = { type = "app"; program = "${twine-env}/bin/twine"; };
      };
    });
}
