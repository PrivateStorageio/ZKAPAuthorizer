{ fetchFromGitHub, autobahn }:
autobahn.overrideAttrs (old: rec {
  pname = "autobahn";
  version = "19.7.1";
  src = fetchFromGitHub {
    owner = "crossbario";
    repo = "autobahn-python";
    rev = "v${version}";
    sha256 = "1gl2m18s77hlpiglh44plv3k6b965n66ylnxbzgvzcdl9jf3l3q3";
  };
})
