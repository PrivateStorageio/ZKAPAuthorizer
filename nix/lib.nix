{ pkgs, lib, mach-nix, src }:
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
    }:
      with pkgs."${pyVersion}Packages";
      let
        tahoe-lafs-package = buildPythonPackage {
          # tahoe-lafs.buildArgs // { python = pyVersion; }
	  pname = "tahoe-lafs";
          version = tahoe-lafs.buildArgs.version;
          src = tahoe-lafs.buildArgs.src;
          propagatedBuildInputs = [
            zfec
            zope_interface
            foolscap
            cryptography
            twisted
            pyyaml
            six
            magic-wormhole
            eliot
            pyrsistent
            attrs
            autobahn
            future
            netifaces
            pyutil
            collections-extended
            klein
            werkzeug
            treq
            cbor2
            (callPackage ./pycddl.nix {})
            click
            psutil
            filelock
          ];
        };
      in
        buildPythonPackage {
        # 	nativeBuildInputs = [ pkgs.breakpointHook ];
        inherit src;
	pname = "ZKAPAuthorizer";
        version = "9001";
        propagatedBuildInputs = [
          prometheus-client
          colorama
          tahoe-lafs-package
          (callPackage ./compose.nix {})
          (callPackage ./tahoe-capabilities.nix {})
          sqlparse
          autobahn
        ];
      };

  # Create a Python environment suitable for running automated tests for the
  # project.
  #
  # AttrSet -> derivation
  pythonTestingEnv =
    { pyVersion          # string, eg "python39"
    , tahoe-lafs
    , requirementsExtra  # string, eg "pudb\n"
    }: mach-nix.mkPython {
    python = pyVersion;
    requirements = ''
    ${requirementsExtra}
    ${builtins.readFile "${src}/requirements/test.in"}
    '';
    packagesExtra = [ (packageForVersion { inherit pyVersion tahoe-lafs; } ) ];
  };

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
    , hypothesisProfile ? null
    , collectCoverage ? false
    , moreArgs ? [ "--rterrors" "--jobs=$NIX_BUILD_CORES" "--force-gc" ]
    , testSuite ? "_zkapauthorizer"
    }:
    let
      testEnv = pythonTestingEnv {
        inherit pyVersion tahoe-lafs;
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
