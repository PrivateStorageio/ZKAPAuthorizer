{ fetchPypi
, buildPythonPackage
, pythonPackages
, zope_interface
, zope_schema
}:
buildPythonPackage rec {
  pname = "mypy-zope";
  version = "0.3.11";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-1CVfnwTUjHkIO71OL+oGUTpqx7jeBvjEzlY/2FFCygU=";
  };

  # doCheck = false;
  propagatedBuildInputs = [ pythonPackages.mypy zope_interface zope_schema ];
  pythonImportsCheck = [ "mypy_zope" ];
}
