{ pkgs ? import <nixpkgs> { } }:
pkgs.stdenv.mkDerivation rec {
  version = "0.0";
  name = "secure-access-token-authorizer-${version}";
  depsBuildBuild = [ pkgs.python37Packages.sphinx ];
}
