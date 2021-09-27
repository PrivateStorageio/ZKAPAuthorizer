{ callPackage }:
let
  repo = callPackage ./repo-1_16_0_rc1.nix { };
  tahoe-lafs = callPackage "${repo}/nix" { };
in
  tahoe-lafs
