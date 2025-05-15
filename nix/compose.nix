{ lib, buildPythonPackage, fetchPypi }:

buildPythonPackage rec {
  pname = "compose";
  version = "1.6.2";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256-yUP6goTByziSklOIhi4gPJiISE5M4/1RcVBnaWkNi00=";
  };

  meta = with lib; {
    homepage = "https://github.com/mentalisttraceur/python-compose";
    description = "The classic compose, with all the Pythonic features.";
    license = licenses.bsd0;
  };
}
