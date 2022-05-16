let
  fixArgs = a: builtins.removeAttrs a [
    # Make sure all the args tests.nix accepts but default.nix does not are
    # listed here so we don't try to forward them to default.nix
    "privatestorage"
    "hypothesisProfile"
    "collectCoverage"
    "testSuite"
    "trialArgs"
  ];
in
{ privatestorage ? import ./. (fixArgs args)
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
# accept any other arguments to be passed on to default.nix
, ...
}@args:
let
    inherit (privatestorage) pkgs mach-nix zkapauthorizer;
    inherit (pkgs) lib;
    hypothesisProfile' = if hypothesisProfile == null then "default" else hypothesisProfile;
    defaultTrialArgs = [ "--rterrors" "--jobs=$NIX_BUILD_CORES" ];
    trialArgs' = if trialArgs == null then defaultTrialArgs else trialArgs;
    extraTrialArgs = builtins.concatStringsSep " " trialArgs';
    testSuite' = if testSuite == null then "_zkapauthorizer" else testSuite;

    coveragerc = builtins.path {
      name = "coveragerc";
      path = ./.coveragerc;
    };
    coverage-env = lib.optionalString collectCoverage "COVERAGE_PROCESS_START=${coveragerc}";
    coverage-cmd = lib.optionalString collectCoverage "coverage run --debug=config --rcfile=${coveragerc} --module";

    python = mach-nix.mkPython {
      inherit (zkapauthorizer.meta.mach-nix) python providers;
      requirements = ''
        ${builtins.readFile ./requirements/test.in}
        ${if collectCoverage then "coverage_enable_subprocess" else ""}
      '';
      packagesExtra = [ zkapauthorizer ];
      _.hypothesis.postUnpack = "";
    };

    lint = pkgs.runCommand "zkapauthorizer-lint" {
      passthru = {
        inherit python;
      };
    } ''
      pushd ${zkapauthorizer.src}
      ${python}/bin/flake8 src
      popd

      touch $out
      '';

    tests = pkgs.runCommand "zkapauthorizer-tests" {
      passthru = {
        inherit python;
      };
    } ''
      mkdir -p $out

      export ZKAPAUTHORIZER_HYPOTHESIS_PROFILE=${hypothesisProfile'}
      ${coverage-env} ${python}/bin/python -m ${coverage-cmd} twisted.trial ${extraTrialArgs} ${testSuite'}

      ${lib.optionalString collectCoverage
        ''
          # Combine straight into the output location, also pointing coverage
          # at the directory that contains all of the files to be combined
          # (necessary) and the configuration file (abundance of caution).
          echo "Combining coverage"
          ${python}/bin/python -m coverage combine \
              --rcfile ${zkapauthorizer.src}/.coveragerc \
              --data-file "$out/.coverage" \
              ./

          # We're in /build and the coverage data is going to tell `coverage
          # html` to look in src/... where it won't find it.  So, make it
          # available beneath that path.
          ln -s ${zkapauthorizer.src}/src

          # Generate an HTML report too.
          echo "Generating HTML report"
          ${python}/bin/python -m coverage html \
              --rcfile ${zkapauthorizer.src}/.coveragerc \
              --data-file "$out/.coverage" \
              --directory "$out/htmlcov"
        ''
      }
    '';
in
{
  inherit privatestorage lint tests;
}
