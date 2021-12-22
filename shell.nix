let
  sources = import nix/sources.nix;
in
{ pkgs ? import sources.release2105 {}
, tahoe-lafs-source ? "tahoe-lafs-1.17.0"
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
