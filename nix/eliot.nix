{
  lib,
  buildPythonPackage,
  fetchFromGitHub,
  pythonOlder,
  aiocontextvars,
  boltons,
  hypothesis,
  pyrsistent,
  pytestCheckHook,
  setuptools,
  six,
  testtools,
  zope-interface,
}:

buildPythonPackage rec {
  pname = "eliot";
  version = "1.15.0";
  format = "setuptools";

  disabled = pythonOlder "3.6";

  src = fetchFromGitHub {
    owner = "itamarst";
    repo = "eliot";
    rev = "1.15.0";
    hash = "sha256-Ur7q7PZ5HH4ttD3b0HyBTe1B7eQ2nEWcTBR/Hjeg9yw=";
  };

  propagatedBuildInputs = [
    aiocontextvars
    boltons
    pyrsistent
    setuptools
    six
    zope-interface
  ];

  nativeCheckInputs = [
    hypothesis
    pytestCheckHook
    testtools
  ];

  pythonImportsCheck = [ "eliot" ];

  # Tests run eliot-prettyprint in out/bin.
  preCheck = ''
    export PATH=$out/bin:$PATH
  '';

  disabledTests = [
    "test_parse_stream"
    # AttributeError: module 'inspect' has no attribute 'getargspec'
    "test_default"
  ];

  meta = with lib; {
    homepage = "https://eliot.readthedocs.io";
    description = "Logging library that tells you why it happened";
    mainProgram = "eliot-prettyprint";
    license = licenses.asl20;
    maintainers = with maintainers; [ dpausp ];
  };
}
