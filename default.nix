{ pkgs ? import <nixpkgs> { }
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
, tahoe-lafs ? "1.14.0"
}:
let
  tahoe-packages = {
    "1.14.0"    = pkgs.python2Packages.tahoe-lafs-1_14;
    "1.16.0rc1" = pkgs.python2Packages.callPackage ./nix/tahoe-lafs-1_16.nix { };
  };
  tahoe-lafs' = builtins.getAttr tahoe-lafs tahoe-packages;

  pkgs' = pkgs.extend (import ./overlays.nix);
  callPackage = pkgs'.python27Packages.callPackage;
in
callPackage ./zkapauthorizer.nix {
  challenge-bypass-ristretto = callPackage ./python-challenge-bypass-ristretto.nix { };
  inherit hypothesisProfile collectCoverage testSuite trialArgs;
  tahoe-lafs = tahoe-lafs';
}
