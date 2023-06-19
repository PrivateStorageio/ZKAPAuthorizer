{ hypothesis, fetchFromGitHub }:
hypothesis.overrideAttrs (old: rec {
  version = "6.74.1";
  name = "hypothesis-${version}";
  src = fetchFromGitHub {
    owner = "HypothesisWorks";
    repo = "hypothesis";
    rev = "hypothesis-python-${version}";
    hash = "sha256-bzbC9TmqqvrgTkJ3aZjp3Dd9MgeGxOkj1bz03Ng2sCo=";
  };
})
