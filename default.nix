let
  sources = import nix/sources.nix;
in
{ pkgs ? import sources.release2111 { }
, pypiData ? sources.pypi-deps-db
, python ? "python39"
, mach-nix ? import sources.mach-nix { inherit pkgs pypiData python; }
, tahoe-lafs-source ? "tahoe-lafs"
, tahoe-lafs-repo ? sources.${tahoe-lafs-source}
, ...
}:
  let
    lib = pkgs.lib;
    providers = {
      # It is convenient to get wheels since they require the least additional
      # processing before installation.  Some packages do not have wheels on
      # PyPI, or they have binary wheels with a platform tag that's not
      # compatible with nixpkgs Python's platform tag (rendering them
      # unusable), so we will also allow building from sdist.
      #
      # We generally don't take things from nixpkgs because when the version
      # required does not match exactly the version in nixpkgs, that source
      # has the greatest chance of failure due to skew between
      # packaging-related definitions in the version in nixpkgs vs the
      # different version we get from elsewhere.
      _default = "wheel,sdist";

      # However, we specifically want to be able to get unreleased versions of
      # tahoe-lafs so we put our own package of that into nixpkgs and then
      # require that mach-nix satisfy a tahoe-lafs dependency from there.
      # This is kind of round-about but it seems to be the best way to
      # convince mach-nix to use a specific package for a specific dependency.
      tahoe-lafs = "nixpkgs";

      # Make sure we use an sdist of zfec so that our patch to zfec's setup.py
      # to remove its argparse dependency can be applied.  If we get a wheel,
      # it is too late to fix that (though I suppose we could fix the metadata
      # in t he wheel if we really wanted to).
      zfec = "sdist";
    };

    # Define some fixes to the packaging / build process of some of the
    # dependencies.  These need to be added to each derivation that might
    # depend on the relevant packages.
    dependency-fixes = {
      _.zfec.patches = [
        (builtins.fetchurl https://github.com/tahoe-lafs/zfec/commit/c3e736a72cccf44b8e1fb7d6c276400204c6bc1e.patch)
      ];
    };

  in
    rec {
      inherit pkgs mach-nix;

      tahoe-lafs = mach-nix.buildPythonPackage rec {
        inherit python providers;
        inherit (dependency-fixes) _;
        name = "tahoe-lafs";
        # We add `.post999` here so that we don't accidentally *exactly* match
        # the upstream Tahoe-LAFS version.  This avoids the misleading
        # circumstance where the version in the Nix packaging *looks* like a
        # real upstream Tahoe-LAFS revision but we have forgotten to update it
        # so it is the *wrong* real upstream Tahoe-LAFS revision.  Hopefully
        # the `.post999` looks weird enough that if someone really cares about
        # the version in use they will notice it and go searching for what's
        # going on and discover the real version specified by `src` below.
        version = "1.17.1.post999";
        # See https://github.com/DavHau/mach-nix/issues/190
        requirementsExtra =
          ''
          # See https://github.com/DavHau/mach-nix/issues/190
          pyrsistent
          configparser
          eliot
          foolscap
          collections-extended >= 2.0.2

          # undetected cryptography build dependency
          # https://github.com/DavHau/mach-nix/issues/305
          setuptools_rust
          # undetected tomli build dependency
          # probably same underlying cause as cryptography issue
          flit_core
          '';
        postPatch = ''
          cat > src/allmydata/_version.py <<EOF
          # This _version.py is generated by nix.

          verstr = "${version}+git-${tahoe-lafs-repo.rev}"
          __version__ = verstr
          EOF
        '';
        src = tahoe-lafs-repo;
      };
      zkapauthorizer = mach-nix.buildPythonApplication rec {
        inherit python providers;
        inherit (dependency-fixes) _;
        src = lib.cleanSource ./.;
        # mach-nix does not provide a way to specify dependencies on other
        # mach-nix packages, that incorporates the requirements and overlays
        # of that package.
        # See https://github.com/DavHau/mach-nix/issues/123
        # In particular, we explicitly include the requirements of tahoe-lafs
        # here, and include it in a python package overlay.
        requirementsExtra = tahoe-lafs.requirements;
        overridesPre = [
          (
            self: super: {
              inherit tahoe-lafs;
            }
          )
        ];
        # Record some settings here, so downstream nix files can consume them.
        meta.mach-nix = { inherit python providers; };
      };

      privatestorage = let
        python-env = mach-nix.mkPython {
          inherit python providers;
          packagesExtra = [ zkapauthorizer tahoe-lafs ];
        };
      in
        # Since we use this derivation in `environment.systemPackages`,
        # we create a derivation that has just the executables we use,
        # to avoid polluting the system PATH with all the executables
        # from our dependencies.
        pkgs.runCommandNoCC "privatestorage" {}
          ''
            mkdir -p $out/bin
            ln -s ${python-env}/bin/tahoe $out/bin
            # Include some tools that are useful for debugging.
            ln -s ${python-env}/bin/flogtool $out/bin
            ln -s ${python-env}/bin/eliot-prettyprint $out/bin
          '';
    }
