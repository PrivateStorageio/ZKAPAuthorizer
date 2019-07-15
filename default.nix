{ pkgs ? import <nixpkgs> { } }:
let
  newpkgs = import pkgs.path { overlays = [ import ./overlays.nix ]; };
in
  pkgs.pythonPackages.callPackage ./secure-access-token-authorizer.nix { }
