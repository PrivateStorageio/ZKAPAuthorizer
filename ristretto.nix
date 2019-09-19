{ fetchFromGitHub, callPackage }:
let
  src = import ./privacypass-repo.nix { inherit fetchFromGitHub; };
in
  callPackage "${src}/ristretto.nix" { }
