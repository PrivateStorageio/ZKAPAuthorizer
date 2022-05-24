args@{ ... }:
let
  sources = import ./nix/sources.nix;
  issuer = (import "${sources.PaymentServer}/nix").PaymentServer;
  zkapauthorizer = import ./. args;
  pkgs = zkapauthorizer.pkgs;
in
pkgs.callPackage ./end-to-end {
  zkapauthorizer = zkapauthorizer.privatestorage;
  inherit issuer;
}
