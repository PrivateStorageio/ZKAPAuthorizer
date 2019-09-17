{ fetchFromGitHub, callPackage }:
let
  src = import ./privacypass-repo.nix { inherit fetchFromGitHub; };
  privacypass = callPackage "${src}" { };
in
  privacypass.overrideAttrs (old: {
    patches = [
      ./remove-setuptools-scm.patch
    ];
  })
