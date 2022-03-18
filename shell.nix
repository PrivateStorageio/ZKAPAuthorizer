# Note: Passing arguments through here to customize the environment does not
# work on Nix 2.3.  It works with Nix 2.5.  I'm not sure about 2.4.
{ ... }@args:
let
  tests = import ./tests.nix args;
  inherit (tests) privatestorage lint-python;
  inherit (privatestorage) pkgs mach-nix tahoe-lafs zkapauthorizer;

  python-env = mach-nix.mkPython {
    inherit (zkapauthorizer.meta.mach-nix) python providers;
    overridesPre = [
      (
        self: super: {
          inherit tahoe-lafs;
        }
      )
    ];
    requirements =
      ''
      ${builtins.readFile ./requirements/test.in}
      ${builtins.readFile ./requirements/elpy.in}
      ${builtins.readFile ./requirements/debug.in}
      ${zkapauthorizer.requirements}
      '';
  };
in
pkgs.mkShell {
  # Avoid leaving .pyc all over the source tree when manually triggering tests
  # runs.
  PYTHONDONTWRITEBYTECODE = "1";

  # Put this source tree into the Python import path, too, for a `setup.py
  # develop`-like experience.
  PYTHONPATH = "${builtins.toString ./.}/src";

  # Make pudb the default.
  PYTHONBREAKPOINT = "pudb.set_trace";

    # Supply all of the runtime and testing dependencies.
  buildInputs = [
    python-env
  ];
}
