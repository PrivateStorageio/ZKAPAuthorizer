let
  pkgs = import <nixpkgs> {};
in
  pkgs.fetchFromGitHub {
    owner = "LeastAuthority";
    repo = "python-challenge-bypass-ristretto";
    rev = "e15f0f02d43cd16e712cde26e87b4854bedff5e6";
    sha256 = "1xrzcf01z2hzhajbnv6csc1dqld8apkvv6x202hjc9y88rb2mmpb";
  }