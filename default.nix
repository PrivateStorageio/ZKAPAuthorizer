{ pkgs ? import <nixpkgs> { }
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
, tahoe-lafs ? ({pythonPackages}: pythonPackages.tahoe-lafs-1_14)
}:
let
  pkgs' = pkgs.extend (import ./overlays.nix);
  callPackage = pkgs'.python27Packages.callPackage;
  tahoe-lafs' = callPackage tahoe-lafs {};
in
callPackage ./zkapauthorizer.nix {
  challenge-bypass-ristretto = callPackage ./python-challenge-bypass-ristretto.nix { };
  inherit hypothesisProfile collectCoverage testSuite trialArgs;
  tahoe-lafs = tahoe-lafs';
}
