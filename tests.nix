{ privatestorage ? import ./. args
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
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

    python = mach-nix.mkPython {
      inherit (zkapauthorizer.meta.mach-nix) python providers;
      requirements =
        builtins.readFile ./requirements/test.in;
      packagesExtra = [ zkapauthorizer ];
      _.hypothesis.postUnpack = "";
    };

    lint-python = mach-nix.mkPython {
      python = "python39";
      requirements = ''
        isort
        black
        flake8
      '';
    };

    tests = pkgs.runCommand "zkapauthorizer-tests" {
      passthru = {
        inherit python;
      };
    } ''
      mkdir -p $out

      pushd ${zkapauthorizer.src}
      ${python}/bin/pyflakes src
      ${lint-python}/bin/black --check src
      ${lint-python}/bin/isort --check src
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
  inherit pkgs python lint-python tests;
}
