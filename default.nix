{ pkgs ? import <nixpkgs> { }
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
, tahoe-lafs ? null
}:
let
  pkgs' = pkgs.extend (import ./overlays.nix);
  callPackage = pkgs'.python27Packages.callPackage;
  tahoe-lafs = if tahoe-lafs == null then pkgs.python2Packages.tahoe-lafs-1_14 else tahoe-lafs;
in
callPackage ./zkapauthorizer.nix {
  challenge-bypass-ristretto = callPackage ./python-challenge-bypass-ristretto.nix { };
  inherit hypothesisProfile collectCoverage testSuite trialArgs tahoe-lafs;
}
