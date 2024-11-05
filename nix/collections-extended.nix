{
  lib,
  buildPythonPackage,
  fetchFromGitHub,
  hypothesis,
  poetry-core,
  pytestCheckHook,
  pythonOlder,
  pythonAtLeast,
}:

buildPythonPackage rec {
  pname = "collections-extended";
  version = "2.0.2.post1";
  format = "pyproject";

  # https://github.com/mlenzen/collections-extended/issues/198
  disabled = pythonOlder "3.6" || pythonAtLeast "3.12";

  src = fetchFromGitHub {
    owner = "mlenzen";
    repo = pname;
    # This version includes our hero JP's patches for Python 3.11.
    rev = "8b93390636d58d28012b8e9d22334ee64ca37d73";
    hash = "sha256-e7RCpNsqyS1d3q0E+uaE4UOEQziueYsRkKEvy3gCHt0=";
  };

  nativeBuildInputs = [ poetry-core ];

  nativeCheckInputs = [
    hypothesis
    pytestCheckHook
  ];

  pythonImportsCheck = [ "collections_extended" ];

  meta = with lib; {
    description = "Extra Python Collections - bags (multisets), setlists (unique list/indexed set), RangeMap and IndexedDict";
    homepage = "https://github.com/mlenzen/collections-extended";
    license = licenses.asl20;
    maintainers = with maintainers; [ exarkun ];
  };
}
