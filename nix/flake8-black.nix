{ fetchPypi
, buildPythonPackage
, flake8
, black
, tomli
, setuptools
, pip
}:
buildPythonPackage rec {
  pname = "flake8-black";
  version = "0.3.6";

  src = fetchPypi {
    inherit pname version;
    hash = "sha256-DfvKMnR3d5KlvLKviHpMrXLHLQ6GyU4I46PeFRu0HDQ=";
  };

  format = "pyproject";
  # doCheck = false;
  buildInputs = [ setuptools pip ];
  propagatedBuildInputs = [ flake8 black tomli ];
  pythonImportsCheck = [ "flake8_black" ];
}
