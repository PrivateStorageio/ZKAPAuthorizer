{ pkgs ? import <nixpkgs> { overlays = [ (import ./overlays.nix) ]; } }:
pkgs.python27Packages.callPackage ./secure-access-token-authorizer.nix { }
