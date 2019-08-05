{ buildPythonPackage, sphinx, circleci-cli
, attrs, zope_interface, twisted, tahoe-lafs
, fixtures, testtools, hypothesis, pyflakes, treq, coverage
}:
buildPythonPackage rec {
  version = "0.0";
  name = "zero-knowledge-access-pass-authorizer-${version}";
  src = ./.;

  depsBuildBuild = [
    sphinx
    circleci-cli
  ];

  propagatedBuildInputs = [
    attrs
    zope_interface
    twisted
    tahoe-lafs
  ];

  checkInputs = [
    coverage
    fixtures
    testtools
    hypothesis
    twisted
    treq
  ];

  checkPhase = ''
    ${pyflakes}/bin/pyflakes src/_zkapauthorizer
    python -m coverage run --source _zkapauthorizer,twisted.plugins.zkapauthorizer --module twisted.trial _zkapauthorizer
  '';
}
