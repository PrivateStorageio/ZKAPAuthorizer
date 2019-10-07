{ pkgs ? import ./nixpkgs.nix { }, hypothesisProfile ? null, collectCoverage ? false }:
pkgs.python27Packages.zkapauthorizer.override { inherit hypothesisProfile collectCoverage; }
