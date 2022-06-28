{ pkgs ? import <nixpkgs> {}
}: {
  twine = pkgs.python3.withPackages (ps: [ ps.twine ]);
}
