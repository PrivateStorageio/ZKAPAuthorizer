let
  sources = import nix/sources.nix;
in
{ pkgs ? import sources.release2015 {}
, pypiData ? sources.pypi-deps-db
, mach-nix ? import sources.mach-nix { inherit pkgs pypiData; }
, zkapauthorizer ? (import ./. { inherit pkgs pypiData mach-nix; }).zkapauthorizer
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
,
}:
  let
    lib = pkgs.lib;
    hypothesisProfile' = if hypothesisProfile == null then "default" else hypothesisProfile;
    defaultTrialArgs = [ "--rterrors" ] ++ (lib.optional (! collectCoverage) "--jobs=$NIX_BUILD_CORES");
    trialArgs' = if trialArgs == null then defaultTrialArgs else trialArgs;
    extraTrialArgs = builtins.concatStringsSep " " trialArgs';
    testSuite' = if testSuite == null then "_zkapauthorizer" else testSuite;

    python = mach-nix.mkPython {
      inherit (zkapauthorizer.meta.mach-nix) python providers;
      requirements =
        builtins.readFile ./requirements/test.in;
      packagesExtra = [ zkapauthorizer ];
      _.hypothesis.postUnpack = "";
    };
  in
    pkgs.runCommand "zkapauthorizer-tests" {
      passthru = {
        inherit python;
      };
    } ''
      mkdir -p $out

      pushd ${zkapauthorizer.src}
      ${python}/bin/pyflakes
      popd

      ZKAPAUTHORIZER_HYPOTHESIS_PROFILE=${hypothesisProfile'} ${python}/bin/python -m ${if collectCoverage
        then "coverage run --debug=config --rcfile=${zkapauthorizer.src}/.coveragerc --module"
        else ""
      } twisted.trial ${extraTrialArgs} ${testSuite'}

      ${lib.optionalString collectCoverage
        ''
          mkdir -p "$out/coverage"
          cp -v .coverage.* "$out/coverage"
        ''
      }
    ''
