{ pkgs, lib, src }:
let
  inherit (import ./sh.nix { inherit lib; }) trial;
in
rec {
  # Return an attrset where the keys are `formatter c` and the corresponding
  # values are `navigate c`.
  #
  # (Coordinate -> string) -> (Coordinate -> a) -> [ Coordinate ] -> { string = a; }
  derivationMatrix = formatter: navigate: coordinates:
    let
      chart = coord: accum: accum // {
        ${formatter coord} = navigate coord;
      };
    in
      lib.foldr chart {} coordinates;

  # The path to the python-coverage configuration file for the project.
  #
  # string
  coveragerc = builtins.path { name = "coveragerc"; path = "${src}/.coveragerc"; };

  # Create a package for the project for the given version of Python.
  #
  # string -> derivation
  packageForVersion =
    { pyVersion
    , tahoe-lafs
    , challenge-bypass-ristretto
    }:
    let python = (pkgs.${pyVersion}.override {
      # super is the unmodified package set that we're about to override some
      # contents of.
      #
      # self is the fixed point of the package set - the result of applying
      # our override recursively to the package set until the return value is
      # the same as the input.
      packageOverrides = self: super: {
        klein = super.klein.overrideAttrs (old: {
          # The klein test suite is a little broken so ... don't run it.
          doInstallCheck = false;
        });
        pycddl = self.callPackage ./pycddl.nix {};
        twisted = self.callPackage ./twisted.nix {
          # Our twisted.nix is defined in terms of twisted so we cannot let
          # self.callPackage pass twisted.  Override that by explicitly
          # passing twisted from super here, instead.
          inherit (super) twisted;
        };

        # The foolscap test suite has one failing test when run against the
        # new version of Twisted, so disable the test suite for now.
        foolscap = super.foolscap.overrideAttrs (old: {
          doInstallCheck = false;
          # XXX Maybe we could just disable the one failing test,
          # Versus.testVersusHTTPServerAuthenticated
        });

        compose = self.callPackage ./compose.nix {};
        tahoe-capabilities = self.callPackage ./tahoe-capabilities.nix {};

        tahoe-lafs-package = self.callPackage ./tahoe-lafs.nix {
          tahoe-lafs-version = tahoe-lafs.buildArgs.version;
          tahoe-lafs-src = tahoe-lafs.buildArgs.src;
          postPatch = tahoe-lafs.buildArgs.postPatch or null;
        };

        flake8-isort = self.callPackage ./flake8-isort.nix {};
        flake8-black = self.callPackage ./flake8-black.nix {};
        mypy-zope = self.callPackage ./mypy-zope.nix {};
        types-PyYAML = self.callPackage ./types-pyyaml.nix {};
      };
    }); in with python.pkgs;
    buildPythonPackage rec {
      inherit src;
      pname = "ZKAPAuthorizer";
      # Don't forget to bump the version number in
      # src/_zkapauthorizer/__init__.py too.
      version = "2022.8.21";
      format = "setuptools";

      # Should this be nativeCheckInputs?  It might matter for
      # cross-compilation.  It's not clear cross-compilation works for Python
      # packages anyway, and no one has asked for it yet so ...
      checkInputs = [
        coverage
        fixtures
        testtools
        testresources
        hypothesis
        openapi-spec-validator
      ];

      checkPhase = ''
        python -m twisted.trial -j$NIX_BUILD_CORES _zkapauthorizer
      '';

      pythonImportsCheck = [ "_zkapauthorizer" ];

      propagatedBuildInputs = [
        prometheus-client
        colorama
        tahoe-lafs-package
        compose
        tahoe-capabilities
        sqlparse
        autobahn
        # It would be nice if we got challenge-bypass-ristretto as
        # something we could `callPackage` but instead we just get a
        # derivation from the python-challenge-bypass-ristretto flake.
        # Handle that case specially here.
        (challenge-bypass-ristretto pyVersion)
      ];

      passthru = {
        python = python;
        inherit checkInputs;
      };
    };

  # Create a Python environment suitable for running automated tests for the
  # project.
  #
  # AttrSet -> derivation
  pythonTestingEnv =
    { pyVersion          # string, eg "python39"
    , tahoe-lafs
    , challenge-bypass-ristretto
    , requirementsExtra  # string, eg "pudb\n"
    }:
    pkgs.${pyVersion}.withPackages (ps: with ps; [
      (packageForVersion { inherit pyVersion tahoe-lafs challenge-bypass-ristretto; } )
      coverage
      fixtures
      testtools
      testresources
      hypothesis
      openapi-spec-validator
   ]);
#    ${requirementsExtra}

  runTests =
    { testEnv
    , hypothesisProfile    # null or string, eg "ci"
    , collectCoverage      # boolean
    , testSuite            # string, eg "_zkapauthorizer"
    , moreArgs             # [string], eg ["--rterrors" "--reporter=subunitv2"]
    }:
    let
      coverageArgs = lib.optionals (collectCoverage) [ "coverage" "run" "--debug=config" "--rcfile=${coveragerc}" "--module" ];
      coverageEnv = lib.optionalAttrs (collectCoverage) { COVERAGE_PROCESS_START = coveragerc; };

      hypothesisEnv = lib.optionalAttrs (hypothesisProfile != null) { ZKAPAUTHORIZER_HYPOTHESIS_PROFILE = hypothesisProfile; };

      envVars = hypothesisEnv // coverageEnv;
      pythonArgs = coverageArgs;
      trialArgs = moreArgs ++ [ testSuite ];
    in
      trial testEnv envVars pythonArgs trialArgs;

  testsForVersion =
    { pyVersion
    , tahoe-lafs
    , challenge-bypass-ristretto
    , hypothesisProfile ? null
    , collectCoverage ? false
    , moreArgs ? [ "--rterrors" "--jobs=$NIX_BUILD_CORES" "--force-gc" ]
    , testSuite ? "_zkapauthorizer"
    }:
    let
      testEnv = pythonTestingEnv {
        inherit pyVersion tahoe-lafs challenge-bypass-ristretto;
        requirementsExtra = lib.optionalString collectCoverage "coverage_enable_subprocess";
      };
      runTestsCommand = runTests {
        inherit testEnv hypothesisProfile collectCoverage moreArgs testSuite;
      };
      processCoverageCommand =
        if collectCoverage
        then
          ''
          # Combine straight into the output location, also pointing coverage
          # at the directory that contains all of the files to be combined
          # (necessary) and the configuration file (abundance of caution).
          echo "Combining coverage"
          ${testEnv}/bin/python -m coverage combine \
              --rcfile ${coveragerc} \
              --data-file "$out/.coverage" \
              ./

          # We're in /build and the coverage data is going to tell `coverage
          # html` to look in src/... where it won't find it.  So, make it
          # available beneath that path.
          ln -s ${src}/src

          # Generate an HTML report too.
          echo "Generating HTML report"
          ${testEnv}/bin/python -m coverage html \
              --rcfile ${coveragerc} \
              --data-file "$out/.coverage" \
              --directory "$out/htmlcov"
          ''
        else
          ''
          mkdir $out
          touch $out/passed
          '';
    in
      pkgs.runCommand "zkapauthorizer-tests" { }
        ''
        ${runTestsCommand}
        ${processCoverageCommand}
        '';

  # Create a derivation for a Python wheel of the Python package in the given
  # derivation.
  #
  # derivation -> derivation
  toWheel = drv:
    let
      build-env = pkgs.python3.withPackages (ps: [
        # something has an undetected six dependency
        ps.six
        ps.setuptools ps.wheel ps.build
      ]);
    in
      pkgs.runCommand "${drv.name}-wheel" { }
        ''
        mkdir $out
        cp -a ${drv.src} ./src
        chmod --recursive u+w ./src
        ${build-env}/bin/python -m build --no-isolation --outdir $out --wheel ./src
        '';
}
