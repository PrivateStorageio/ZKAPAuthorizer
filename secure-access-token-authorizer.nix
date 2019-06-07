{ buildPythonPackage, sphinx }:
buildPythonPackage rec {
  version = "0.0";
  name = "secure-access-token-authorizer-${version}";
  src = ./.;
  depsBuildBuild = [ sphinx ];
}
