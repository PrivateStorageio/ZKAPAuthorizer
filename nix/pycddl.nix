{ lib, buildPythonPackage, fetchPypi, rustPlatform, cddl, pkg-config }:

buildPythonPackage rec {
  pname = "pycddl";
  version = "0.4.0";
  format = "pyproject";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-w0CGbPeiXyS74HqZXyiXhvaAMUaIj5onwjl9gWKAjqY=";
  };

  nativeBuildInputs = [
    pkg-config
    cddl
  ] ++ (with rustPlatform; [
    # cargoSetupHook
    maturinBuildHook
  ]);

  meta = with lib; {
    homepage = "https://gitlab.com/tahoe-lafs/pycddl";
    description = "A CDDL validation library for Python";
    license = licenses.mit;
  };
}
