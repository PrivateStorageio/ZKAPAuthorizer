let
  pkgs = import <nixpkgs> {};
in
  pkgs.fetchFromGitHub {
    owner = "tahoe-lafs";
    repo = "tahoe-lafs";
    rev = "34aeefd3ddbf28dafbc3477e52461eafa53b545d";
    sha256 = "0l8n4njbzgiwmn3qsmvzyzqlb0y9bj9g2jvpdynvsn1ggxrqmvsq";
  }