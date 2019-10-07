{ pkgs ? import ./nixpkgs.nix { }, hypothesisProfile ? null, collectCoverage ? false }:
pkgs.python27Packages.callPackage ./zkapauthorizer.nix { inherit hypothesisProfile collectCoverage; }
