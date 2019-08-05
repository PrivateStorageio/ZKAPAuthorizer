{ buildPythonPackage, sphinx, circleci-cli
, attrs, zope_interface, twisted, tahoe-lafs
, fixtures, testtools, hypothesis, pyflakes, treq, coverage
}:
buildPythonPackage rec {
  version = "0.0";
  name = "secure-access-token-authorizer-${version}";
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
    ${pyflakes}/bin/pyflakes src/_secureaccesstokenauthorizer
    python -m coverage run --source _secureaccesstokenauthorizer,twisted.plugins.secureaccesstokenauthorizer --module twisted.trial _secureaccesstokenauthorizer
  '';
}
