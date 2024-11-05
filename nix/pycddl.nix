{ lib, fetchPypi, buildPythonPackage, rustPlatform }:
buildPythonPackage rec {
  pname = "pycddl";
  version = "0.6.3";
  format = "pyproject";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-lVybSr+QvyepdTZfiTjqU0ENu6TT87ZZXIECBA8nMV4=";
  };

  nativeBuildInputs = with rustPlatform; [
    maturinBuildHook
    cargoSetupHook
  ];

  cargoDeps = rustPlatform.fetchCargoTarball {
    inherit src;
    name = "${pname}-${version}";
    hash = "sha256-VpJ/PLAwwuakwsNAtLDdWGXCxl6jGMTvsEhzIHk6a0g=";
  };
}
