{ pkgs ? import <nixpkgs> { }
, hypothesisProfile ? null
, collectCoverage ? false
, testSuite ? null
, trialArgs ? null
}:
let pkgs' = pkgs.extend (import ./overlays.nix);
in pkgs'.python27Packages.zkapauthorizer.override {
  inherit hypothesisProfile collectCoverage testSuite trialArgs;
}
