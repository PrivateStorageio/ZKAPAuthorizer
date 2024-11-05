{ fetchPypi
, buildPythonPackage
, pythonPackages
, zope_interface
, zope_schema
}:
buildPythonPackage rec {
  pname = "mypy_zope";
  version = "1.0.9";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-N9aYXfsFpMJ7Nc/0dXf9W62HjbSJPd7fVNFl9ziaHNs=";
  };

  # doCheck = false;
  propagatedBuildInputs = [ pythonPackages.mypy zope_interface zope_schema ];
  pythonImportsCheck = [ "mypy_zope" ];
}
