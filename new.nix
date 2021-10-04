let
  sources = import nix/sources.nix;
in
{ pkgs ? import sources.release2015 {}
, pypiData ? sources.pypi-deps-db
, mach-nix ? import sources.mach-nix { inherit pkgs pypiData; }
,
}:
    mach-nix.buildPythonApplication rec {
      python = "python27";
      name = "zero-knowledge-access-pass-authorizer";
      src = ./.;
      providers = {
        _default = "sdist,nixpkgs,wheel";
        # not packaged in nixpkgs at all, we can use the binary wheel from
        # pypi though.
        python-challenge-bypass-ristretto = "wheel";
        # Pure python packages that don't build correctly from sdists
        # - patches in nixpkgs that don't apply
        # - missing build dependencies
        # "backports_functools_lru_cache" = "wheel";
        platformdirs = "wheel";
        boltons = "wheel";
        klein = "wheel";
        humanize = "wheel";
        chardet = "wheel";
        urllib3 = "wheel";
        # zipp = "wheel";
        # tqdm = "wheel";
        # FIMXE
      };
      _.tahoe-lafs.patches = [
        (
          pkgs.fetchpatch {
            url = "https://raw.githubusercontent.com/PrivateStorageio/nixpkgs/privatestorageio/pkgs/development/python-modules/tahoe-lafs/rsa-exponent.patch";
            sha256 = "sha256-0vIMj5gZPbKLkow6wpA+Tz7bpyy+mZRSSFGmpg0VMyk=";
          }
        )
      ];
      format = "setuptools";
      requirements = builtins.readFile ./requirements/base.txt;
      # Record some settings here, so downstream nix files can consume them.
      meta.mach-nix = { inherit python providers; };
    }
