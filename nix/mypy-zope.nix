{ fetchPypi
, buildPythonPackage
, pythonPackages
, zope_interface
, zope_schema
}:
buildPythonPackage rec {
  pname = "mypy-zope";
  version = "0.9.1";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-TIfbxx/sNfZTN0bs351ADNkoEzjXHBa1Z2u17QCpfKI=";
  };

  # doCheck = false;
  propagatedBuildInputs = []; # [ pythonPackages.mypy zope_interface zope_schema ];
  pythonImportsCheck = [ "mypy_zope" ];
}
