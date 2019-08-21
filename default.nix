{ pkgs ? import ./nixpkgs.nix { } }:
pkgs.python27Packages.callPackage ./zkapauthorizer.nix { }
