{ pkgs ? import <nixpkgs> { } }:
let
  eliot = pkgs.pythonPackages.callPackage ./eliot.nix { };

  # tahoe-lafs in nixpkgs is packaged as an application!  so we have to
  # re-package it ourselves as a library.
  tahoe-lafs = pkgs.pythonPackages.callPackage ./tahoe-lafs.nix {
    inherit eliot;
  };

in
  pkgs.pythonPackages.callPackage ./secure-access-token-authorizer.nix {
    inherit tahoe-lafs;
  }
