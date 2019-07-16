{ buildPythonPackage, sphinx, circleci-cli
, attrs, zope_interface, twisted, tahoe-lafs
, fixtures, testtools, hypothesis, pyflakes
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
    fixtures
    testtools
    hypothesis
  ];

  checkPhase = ''
    ${pyflakes}/bin/pyflakes src/_secureaccesstokenauthorizer
    ${twisted}/bin/trial _secureaccesstokenauthorizer
  '';
}
