{ callPackage }:
let
  src = import ./python-challenge-bypass-ristretto-repo.nix;
  python-challenge-bypass-ristretto = callPackage "${src}" { };
in
  python-challenge-bypass-ristretto.overrideAttrs (old: {
    patches = [
      ./remove-setuptools-scm.patch
    ];
  })
