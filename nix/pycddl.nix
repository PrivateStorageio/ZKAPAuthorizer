{ lib, buildPythonPackage, fetchurl, rustPlatform, cddl, pkg-config }:

buildPythonPackage rec {
  pname = "pycddl";
  version = "0.4.0";
  format = "wheel";

  src = fetchurl {
    url = "https://files.pythonhosted.org/packages/d6/77/33798b29606bbee6661cf5961e2c4c79d7318727ae04c8046ed35bca7bf0/pycddl-0.4.0-cp310-cp310-manylinux_2_17_x86_64.manylinux2014_x86_64.whl";
    hash = "sha256-4faWDgABRwfLgRnRFXL45F2ylTBCXy4+Yayu6Re8/7Q=";
  };

  meta = with lib; {
    homepage = "https://gitlab.com/tahoe-lafs/pycddl";
    description = "A CDDL validation library for Python";
    license = licenses.mit;
  };
}
