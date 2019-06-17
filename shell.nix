{ pkgs ? import <nixpkgs> { } }:
let
  satauthorizer = pkgs.callPackage ./default.nix { };
in
  (pkgs.python27.buildEnv.override {
    extraLibs = [
      pkgs.python27Packages.fixtures
      pkgs.python27Packages.testtools
      pkgs.python27Packages.hypothesis
      satauthorizer
    ];
    ignoreCollisions = true;
  }).env
