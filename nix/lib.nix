{ system, pkgs }:
let
  python-env = pkgs.python3.withPackages (ps: [ ps.setuptools ps.wheel ps.build ]);
in {
  toWheel = drv:
    pkgs.runCommand "${drv.name}-wheel" { }
      ''
      mkdir $out
      cp -a ${drv.src} ./src
      chmod --recursive u+w ./src
      ${python-env}/bin/python -m build --no-isolation --outdir $out --wheel ./src
      '';
}
