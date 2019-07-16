{ pkgs ? import <nixpkgs> { overlays = [ (import ./overlays.nix) ]; } }:
let
  satauthorizer = pkgs.callPackage ./default.nix { };
in
  (pkgs.python27.buildEnv.override {
    extraLibs = with pkgs.python27Packages; [
      fixtures
      testtools
      hypothesis
      pyhamcrest
      satauthorizer
    ];
    ignoreCollisions = true;
  }).env
