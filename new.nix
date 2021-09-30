let
  sources = import nix/sources.nix;
in
{ pkgs ? import sources.release2015 {}
, pypiData ? sources.pypi-deps-db
, mach-nix ? import sources.mach-nix { inherit pkgs pypiData; python = "python27"; }
,
}:
  let
    python-challenge-bypass-ristretto =
      (
        mach-nix.buildPythonPackage rec {
          nativeBuildInputs = [
            pkgs.git
            pkgs.rustPlatform.rust.rustc
            pkgs.rustPlatform.rust.cargo
          ];
          buildInputs = [
            pkgs.rustPlatform.cargoSetupHook
            pkgs.python2.pkgs.milksnake
            pkgs.python2.pkgs.setuptools-scm
          ];
          cargoRoot = "challenge-bypass-ristretto-ffi";
          cargoDeps = pkgs.rustPlatform.fetchCargoTarball {
            inherit src;
            sourceRoot = "source/${cargoRoot}";
            sha256 = "sha256-ewqfNMaOZyNSs8epaviER63iUzljr4fbOeWd3WXYDO4=";
          };
          format = "setuptools";
          src = pkgs.fetchFromGitHub {
            owner = "LeastAuthority";
            repo = "python-challenge-bypass-ristretto";
            rev = "02482f4afe72521377d5bbe2dc1402fecd4c6a9a";
            sha256 = "sha256-PtyC1fk/WAOZvsCc2vK3XNDt/V21DT5Txdo09LmO8bc=";
            fetchSubmodules = true;
            leaveDotGit = true;
          };
          version = "2021.07.12";
        }
      );
  in
    mach-nix.buildPythonApplication rec {
      name = "zero-knowledge-access-pass-authorizer";
      src = ./.;
      providers = {
        _default = "sdist,nixpkgs,wheel";
        # Pure python packages that don't build correctly from sdists
        # - patches in nixpkgs that don't apply
        # - missing build dependencies
        platformdirs = "wheel";
        boltons = "wheel";
        klein = "wheel";
        humanize = "wheel";
        chardet = "wheel";
        urllib3 = "wheel";
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
      overridesPre = [ (self: super: { inherit python-challenge-bypass-ristretto; }) ];
      requirements = builtins.readFile ./requirements/base.txt;
      # Record some settings here, so downstream nix files can consume them.
      #meta.mach-nix = { inherit python providers; };
    }
