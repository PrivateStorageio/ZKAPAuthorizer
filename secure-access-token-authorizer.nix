{ buildPythonPackage, sphinx, circleci-cli, pythonPackages, tahoe-lafs }:
buildPythonPackage rec {
  version = "0.0";
  name = "secure-access-token-authorizer-${version}";
  src = ./.;
  depsBuildBuild = [
    sphinx
    circleci-cli
  ];

  propagatedBuildInputs = with pythonPackages; [
    attrs
    zope_interface
    twisted
    tahoe-lafs
  ];

  checkInputs = with pythonPackages; [
    fixtures
    testtools
    hypothesis
  ];

  checkPhase = ''
    ${pythonPackages.pyflakes}/bin/pyflakes src/_secureaccesstokenauthorizer
    ${pythonPackages.twisted}/bin/trial _secureaccesstokenauthorizer
  '';
}
