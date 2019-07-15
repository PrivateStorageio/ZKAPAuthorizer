{ fetchFromGitHub, cryptography }:
cryptography.overrideAttrs (old: rec {
  pname = "cryptography";
  version = "2.7";
  src = fetchFromGitHub {
    owner = "pyca";
    repo = "cryptography";
    rev = "2.7";
    sha256 = "145byri5c3b8m6dbhwb6yxrv9jrr652l3z1w16mz205z8dz38qja";
  };
})
