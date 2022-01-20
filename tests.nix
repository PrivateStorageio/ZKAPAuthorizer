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
  sources = import nix/sources.nix;
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
    defaultTrialArgs = [ "--rterrors" ] ++ (lib.optional (! collectCoverage) "--jobs=$(($NIX_BUILD_CORES > 8 ? 8 : $NIX_BUILD_CORES))");
    trialArgs' = if trialArgs == null then defaultTrialArgs else trialArgs;
    extraTrialArgs = builtins.concatStringsSep " " trialArgs';
    testSuite' = if testSuite == null then "_zkapauthorizer" else testSuite;

    zss = import sources.zkap-spending-service {
      inherit pkgs mach-nix;
    };

    python = mach-nix.mkPython {
      inherit (zkapauthorizer.meta.mach-nix) python providers;
      requirements =
        builtins.readFile ./requirements/test.in;
      packagesExtra = [ zkapauthorizer ];
      overridesPre = [
        (
          self: super: {
            zkap-spending-service = zss;
          }
        )
      ];
      _.hypothesis.postUnpack = "";
    };

    tests = pkgs.runCommand "zkapauthorizer-tests" {
      passthru = {
        inherit python;
      };
    } ''
      mkdir -p $out

      pushd ${zkapauthorizer.src}
      ${python}/bin/flake8 src
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
    '';
in
{
  inherit privatestorage tests;
}
