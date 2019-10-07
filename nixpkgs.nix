{ pkgs ? import <nixpkgs> { } }:
let
  nixpkgs = pkgs.path;
  args =
  { overlays = [ (import ./overlays.nix) ];
  };
in
pkgs.callPackage nixpkgs args
