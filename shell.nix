{ pkgs ? import ./nixpkgs.nix { } }:
let
  zkapauthorizer = pkgs.callPackage ./default.nix { };
in
  (pkgs.python27.buildEnv.override {
    extraLibs = with pkgs.python27Packages; [
      fixtures
      testtools
      hypothesis
      pyhamcrest
      zkapauthorizer
    ];
    ignoreCollisions = true;
  }).env
