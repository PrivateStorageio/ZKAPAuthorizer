{
  lib,
  stdenv,
  buildPythonPackage,
  fetchFromGitHub,
  fetchpatch,
  setuptools,
  six,
  attrs,
  twisted,
  autobahn,
  treq,
  mock,
  pythonOlder,
  pythonAtLeast,
  pytestCheckHook,
}:

buildPythonPackage rec {
  pname = "magic-wormhole-mailbox-server";
  version = "0.4.1.post1";
  pyproject = true;

  # python 3.12 support: https://github.com/magic-wormhole/magic-wormhole-mailbox-server/issues/41
  disabled = pythonOlder "3.7" || pythonAtLeast "3.13";

  src = fetchFromGitHub {
    owner = "magic-wormhole";
    repo = "magic-wormhole-mailbox-server";
    rev = "30ecb6e3f6f487c915e7ff0acdf2e630cbe17dc8";
    hash = "sha256-AKdGmr9wCf6VBpeLWr9gxtxhZYLDJh9O2GXwOqliYUA=";
  };

  nativeBuildInputs = [ setuptools ];

  propagatedBuildInputs = [
    attrs
    six
    twisted
    autobahn
  ] ++ autobahn.optional-dependencies.twisted ++ twisted.optional-dependencies.tls;

  pythonImportsCheck = [ "wormhole_mailbox_server" ];

  nativeCheckInputs = [
    pytestCheckHook
    treq
    mock
  ];

  disabledTestPaths = lib.optionals stdenv.isDarwin [
    # these tests fail in Darwin's sandbox
    "src/wormhole_mailbox_server/test/test_web.py"
  ];

  meta = {
    description = "Securely transfer data between computers";
    homepage = "https://github.com/magic-wormhole/magic-wormhole-mailbox-server";
    changelog = "https://github.com/magic-wormhole/magic-wormhole-mailbox-server/blob/${version}/NEWS.md";
    license = lib.licenses.mit;
    maintainers = [ lib.maintainers.mjoerg ];
  };
}
