{ callPackage }:
let
  src = import ./privacypass-repo.nix;
  privacypass = callPackage "${src}" { };
in
  privacypass.overrideAttrs (old: {
    patches = [
      ./remove-setuptools-scm.patch
    ];
  })
