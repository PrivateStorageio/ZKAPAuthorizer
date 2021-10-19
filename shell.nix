let
  sources = import nix/sources.nix;
in
{ pkgs ? import sources.release2015 {}
, tahoe-lafs-source ? "tahoe-lafs"
}:
  let
    tests = pkgs.callPackage ./tests.nix {
      inherit tahoe-lafs-source;
    };
  in
    pkgs.mkShell {
      packages = [
        tests.python
        pkgs.niv
      ];
    }
