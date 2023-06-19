{ lib, buildPythonPackage, fetchPypi, attrs }:

buildPythonPackage rec {
  pname = "tahoe-capabilities";
  version = "2023.1.5";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-PdHCrznvsiOmdySrJOXB9GcDXfxqJPOUG0rL/8S/3D8=";
  };

  propagatedBuildInputs = [ attrs ];

  meta = with lib; {
    homepage = "https://github.com/tahoe-lafs/tahoe-capabilities";
    description = "Simple, re-usable types for interacting with Tahoe-LAFS capabilities";
    license = licenses.gpl2;
  };
}
