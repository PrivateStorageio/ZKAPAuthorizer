args@{ ... }:
let
  zkapauthorizer = import ./. args;
  pkgs = zkapauthorizer.pkgs;
in
pkgs.callPackage ./end-to-end {
  zkapauthorizer = zkapauthorizer.privatestorage;
}
