# Note: Passing arguments through here to customize the environment does not
# work on Nix 2.3.  It works with Nix 2.5.  I'm not sure about 2.4.
{ ... }@args:
let
  privatestorage = import ./. args;
  inherit (privatestorage) pkgs mach-nix tahoe-lafs zkapauthorizer;

  pythonVersion = zkapauthorizer.meta.mach-nix.python;

  python = mach-nix.mkPython {
    inherit (zkapauthorizer.meta.mach-nix) providers;
    python = pythonVersion;
    overridesPre = [
      (
        self: super: {
          inherit tahoe-lafs;
        }
      )
    ];

    requirements = let
      py3 = pythonVersion > "python3";
      lint = pkgs.lib.optionalString (builtins.trace py3 py3) ''
# lint
black
isort
flake8
'';
      workarounds = ''
# Mitigate for undetected cryptography dependency
setuptools_rust
# And for tomli
flit_core
'';
      testing = ''
coverage
fixtures
testtools
hypothesis
'';
    in
      ''
${lint}
${workarounds}
${testing}
${zkapauthorizer.requirements}
'';
  };
in
pkgs.mkShell {
  PYTHONDONTWRITEBYTECODE = "1";

  buildInputs = [
    python
  ];
}
