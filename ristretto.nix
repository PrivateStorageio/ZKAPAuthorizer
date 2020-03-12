{ fetchFromGitHub, callPackage }:
let
  src = import ./python-challenge-bypass-ristretto-repo.nix { inherit fetchFromGitHub; };
in
  callPackage "${src}/challenge-bypass-ristretto.nix" { }
