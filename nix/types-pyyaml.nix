{ fetchPypi
, buildPythonPackage
}:
buildPythonPackage rec {
  pname = "types-PyYAML";
  version = "6.0.12.9";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-xRsb1tmd3wqiiEp6MogQ6/cKQmLCkhldP0+aAAX57rY=";
  };
}
