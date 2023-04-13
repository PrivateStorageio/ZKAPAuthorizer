{ fetchPypi
, buildPythonPackage
, flake8
, isort
}:
buildPythonPackage rec {
  pname = "flake8-isort";
  version = "6.0.0";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-U39FOmYNfpA/YC7Po2E2sUDeJ531jQLrG2oMhOg8Uow=";
  };

  doCheck = false;
  propagatedBuildInputs = [ flake8 isort ];
  pythonImportsCheck = [ "flake8_isort" ];
}
