let
  sources = import nix/sources.nix;
in
{ pkgs ? import sources.release2015 {}
, pypiData ? sources.pypi-deps-db
, mach-nix ? import sources.mach-nix { inherit pkgs pypiData; }
, tahoe-lafs-source ? "tahoe-lafs"
, tahoe-lafs-repo ? sources.${tahoe-lafs-source}
, privatestorage ? import ./. {
    inherit pkgs pypiData mach-nix;
    inherit tahoe-lafs-repo;
  }
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
,
}:
  let
    inherit (pkgs) lib;
    inherit (privatestorage) zkapauthorizer;
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

    lint-python = mach-nix.mkPython {
      python = "python39";
      requirements = ''
        isort
        black
      '';
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
    ''
