{ pkgs ? import <nixpkgs> { }
}: let
  utils = pkgs.callPackage ./nix/lib.nix { };
in
  utils.toWheel (import ./. { }).zkapauthorizer
