let
  sources = import nix/sources.nix;
in
{
  pkgs ? import sources.release2015 { },
  pypiData ? sources.pypi-deps-db,
  mach-nix ? import sources.mach-nix { inherit pkgs pypiData; },
  zkapauthorizer ? import ./new.nix { inherit pkgs pypiData mach-nix; },
  ci-reports ? false,
  hypothesisProfile ? null,
  collectCoverage ? false,
  testSuite ? null,
  trialArgs ? null,
}:
let
  lib = pkgs.lib;
  hypothesisProfile' = if hypothesisProfile == null then "default" else hypothesisProfile;
  defaultTrialArgs = [ "--rterrors" ] ++ ( lib.optional ( ! collectCoverage ) "--jobs=$NIX_BUILD_CORES" );
  trialArgs' = if trialArgs == null then defaultTrialArgs else trialArgs;
  extraTrialArgs = builtins.concatStringsSep " " trialArgs';
  testSuite' = if testSuite == null then "_zkapauthorizer" else testSuite;

  python = mach-nix.mkPython {
    inherit (zkapauthorizer.meta.mach-nix) python providers;
    requirements =
      builtins.readFile ./requirements/test.txt;
    packagesExtra = [ zkapauthorizer ];
  };
in
  pkgs.runCommand "zkapauthorizer-tests" {
    # When running in CI, we want `nix build` to succeed and create the `result` symlink
    # even if the tests fail. `succeedOnFailure` will create a `nix-support/failed` file
    # with the exit code, which is read by the CI command to propogate the exit status.
    succeedOnFailure = ci-reports;
  } ''
    ${if ci-reports then
      ''
        mkdir -p $out/codeclimate
        flake8_args+="--format=gl-codeclimate --output-file $out/codeclimate/flake8.json"
      ''
      else
      ''
        mkdir -p $out
        flake8_args+="--tee --output-file $out/flake8.txt"
      ''
    }
    pushd ${zkapauthorizer.src}
    ${python}/bin/flake8 $flake8_args
    popd

    ZKAPAUTHORIZER_HYPOTHESIS_PROFILE=${hypothesisProfile'} ${python}/bin/python -m ${if collectCoverage
      then "coverage run --debug=config --module"
      else ""
    } twisted.trial ${extraTrialArgs} ${testSuite'}
  ''
