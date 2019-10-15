{ pkgs ? import ./nixpkgs.nix { }, hypothesisProfile ? null, collectCoverage ? false, testSuite ? null }:
pkgs.python27Packages.zkapauthorizer.override { inherit hypothesisProfile collectCoverage testSuite; }
