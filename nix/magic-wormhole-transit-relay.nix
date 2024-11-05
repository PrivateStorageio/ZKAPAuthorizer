{
  lib,
  buildPythonPackage,
  fetchFromGitHub,
  setuptools,
  autobahn,
  mock,
  twisted,
  pythonOlder,
  pythonAtLeast,
  pytestCheckHook,
}:

buildPythonPackage rec {
  pname = "magic-wormhole-transit-relay";
  version = "0.3.1.post1";
  pyproject = true;

  disabled = pythonOlder "3.7" || pythonAtLeast "3.13";

  src = fetchFromGitHub {
    owner = "magic-wormhole";
    repo = "magic-wormhole-transit-relay";
    rev = "3b298558e419b0f575f4026be02dd369a4e5f245";
    hash = "sha256-xPpA1rajFDYdlIoyqYNwZ1VmC2bQRC1qR61H15adn1g=";
  };

  nativeBuildInputs = [ setuptools ];

  propagatedBuildInputs = [
    autobahn
    twisted
  ];

  pythonImportsCheck = [ "wormhole_transit_relay" ];

  nativeCheckInputs = [
    pytestCheckHook
    mock
    twisted
  ];

  meta = {
    description = "Transit Relay server for Magic-Wormhole";
    homepage = "https://github.com/magic-wormhole/magic-wormhole-transit-relay";
    changelog = "https://github.com/magic-wormhole/magic-wormhole-transit-relay/blob/${version}/NEWS.md";
    license = lib.licenses.mit;
    maintainers = [ lib.maintainers.mjoerg ];
  };
}
