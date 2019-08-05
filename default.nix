{ pkgs ? import <nixpkgs> { overlays = [ (import ./overlays.nix) ]; } }:
pkgs.python27Packages.callPackage ./zkapauthorizer.nix { }
