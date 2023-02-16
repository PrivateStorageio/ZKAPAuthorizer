{ lib, buildPythonPackage, fetchPypi }:

buildPythonPackage rec {
  pname = "compose";
  version = "1.4.8";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-mpRabfC4LE6xYlHmQbHb1yXxLDtH5idwN4GbUnCPGTo=";
  };

  # doCheck = false;

  meta = with lib; {
    homepage = "https://github.com/mentalisttraceur/python-compose";
    description = "The classic compose, with all the Pythonic features.";
    license = licenses.bsd0;
  };
}
