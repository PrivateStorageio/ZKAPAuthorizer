{ fetchPypi
, buildPythonPackage
}:
buildPythonPackage rec {
  pname = "types-PyYAML";
  version = "6.0.12.20240917";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-0UBahvlXZoIjTvg7y05v/3yTBcix+61eC81Pfb3JxYc=";
  };
}
