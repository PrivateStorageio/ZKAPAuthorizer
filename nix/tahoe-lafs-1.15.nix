{ callPackage, fetchFromGitHub }:
let
  repo = fetchFromGitHub {
    owner = "tahoe-lafs";
    repo = "tahoe-lafs";
    rev = "tahoe-lafs-1.15.1";
    sha256 = "1kaz21gljxwwldfs8bigyzvqs1h70d66jlj01b6m2bwn98l50m0s";
  };
  tahoe-lafs = callPackage "${repo}/nix" { };
  tahoe-lafs-fixed = tahoe-lafs.overrideAttrs (old: rec {
    # Upstream is versioned as 1.14.0.dev, still, even though it is now
    # 1.15.1.
    version = "1.15.1";
    name = "tahoe-lafs-1.15.1";
    postPatch = ''
      ${old.postPatch}

      # We got rid of our .git directory so the built-in version computing logic
      # won't work.  The exact strings we emit here matter because of custom
      # parsing Tahoe-LAFS applies.
      echo 'verstr = "${version}"' > src/allmydata/_version.py
      echo '__version__ = verstr' >> src/allmydata/_version.py
    '';
  });
in
  tahoe-lafs-fixed
