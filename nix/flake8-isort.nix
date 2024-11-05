{ fetchPypi
, buildPythonPackage
, flake8
, isort
}:
buildPythonPackage rec {
  pname = "flake8-isort";
  version = "6.1.0";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-1GOTQ7rFQBlMWfsWGKwsKFs+J2CfNTvvb1CQTUDBZD4=";
  };

  doCheck = false;
  propagatedBuildInputs = [ flake8 isort ];
  pythonImportsCheck = [ "flake8_isort" ];
}
