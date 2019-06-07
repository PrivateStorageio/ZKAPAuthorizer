{ pkgs ? import <nixpkgs> { } }:
pkgs.python37Packages.callPackage ./secure-access-token-authorizer.nix { }
