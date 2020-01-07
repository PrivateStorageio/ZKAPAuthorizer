let
  pkgs = import <nixpkgs> {};
in
  pkgs.fetchFromGitHub {
    owner = "LeastAuthority";
    repo = "privacypass";
    rev = "17ee180eda6dc9ff30d86b9666ee5c0d511434dc";
    sha256 = "0yz2pdm3q8z7cs0cl8aw3k6x6rb9zq088bvis3f6vaaidzd061h6";
  }