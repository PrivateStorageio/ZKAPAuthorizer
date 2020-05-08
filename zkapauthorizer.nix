{ lib
, buildPythonPackage, sphinx, git
, attrs, zope_interface, aniso8601, twisted, tahoe-lafs, challenge-bypass-ristretto, treq
, fixtures, testtools, hypothesis, pyflakes, coverage
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
}:
let
  hypothesisProfile' = if hypothesisProfile == null then "default" else hypothesisProfile;
  testSuite' = if testSuite == null then "_zkapauthorizer" else testSuite;
  defaultTrialArgs = [ "--rterrors" ] ++ ( lib.optional ( ! collectCoverage ) "--jobs=$NIX_BUILD_CORES" );
  trialArgs' = if trialArgs == null then defaultTrialArgs else trialArgs;
  extraTrialArgs = builtins.concatStringsSep " " trialArgs';
in
buildPythonPackage rec {
  version = "0.0";
  pname = "zero-knowledge-access-pass-authorizer";
  name = "${pname}-${version}";
  src = ./.;

  outputs = [ "out" ] ++ (if collectCoverage then [ "doc" ] else [ ]);

  depsBuildBuild = [
    git
    sphinx
  ];

  patches = [
    # Remove the Tahoe-LAFS version pin in distutils config.  We have our own
    # pinning and also our Tahoe-LAFS package has a bogus version number. :/
    ./nix/setup.cfg.patch
  ];

  propagatedBuildInputs = [
    attrs
    zope_interface
    aniso8601
    # Inherit eliot from tahoe-lafs
    # eliot
    twisted
    tahoe-lafs
    challenge-bypass-ristretto
    treq
  ];

  checkInputs = [
    coverage
    fixtures
    testtools
    hypothesis
  ];

  checkPhase = ''
    runHook preCheck
    "${pyflakes}/bin/pyflakes" src/_zkapauthorizer
    ZKAPAUTHORIZER_HYPOTHESIS_PROFILE=${hypothesisProfile'} python -m ${if collectCoverage
      then "coverage run --debug=config --module"
      else ""
    } twisted.trial ${extraTrialArgs} ${testSuite'}
    runHook postCheck
  '';

  postCheck = if collectCoverage
    then ''
    mkdir -p "$doc/share/doc/${name}"
    cp -v .coverage.* "$doc/share/doc/${name}"
    ''
    else "";
}
