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
    zope_interface
    twisted
    tahoe-lafs
  ];

  checkInputs = with pythonPackages; [
    testtools
  ];

  checkPhase = ''
    ${pythonPackages.twisted}/bin/trial _secureaccesstokenauthorizer
  '';
}
