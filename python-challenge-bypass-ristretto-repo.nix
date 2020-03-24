let
  pkgs = import <nixpkgs> {};
in
  pkgs.fetchFromGitHub {
    owner = "LeastAuthority";
    repo = "python-challenge-bypass-ristretto";
    rev = "f1a7cfab1a7f1bf8b3345c228c2183064889ad83";
    sha256 = "12myak2jwaisljs7bmx1vydgd0fnxvkaisk4zsf0kshwxrlnyh3x";
  }