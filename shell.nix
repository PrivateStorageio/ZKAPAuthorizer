# Note: Passing arguments through here to customize the environment does not
# work on Nix 2.3.  It works with Nix 2.5.  I'm not sure about 2.4.
{ ... }@args:
let
  tests = import ./tests.nix args;
  inherit (tests) pkgs;
in
pkgs.mkShell {
  packages = [
    tests.python
    tests.lint-python
    pkgs.niv
  ];
}
