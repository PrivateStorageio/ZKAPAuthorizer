{ pkgs ? import <nixpkgs> { } }:
(pkgs.python27.buildEnv.override {
  extraLibs = [
    (pkgs.callPackage ./default.nix { })
  ];
  ignoreCollisions = true;
}).env
