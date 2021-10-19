let
  sources = import nix/sources.nix;
in
{ pkgs ? import sources.release2015 {} }:
  let
    tests = pkgs.callPackage ./tests.nix {};
  in
    pkgs.mkShell {
      packages = [
        tests.python
        pkgs.niv
      ];
    }
