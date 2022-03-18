# Note: Passing arguments through here to customize the environment does not
# work on Nix 2.3.  It works with Nix 2.5.  I'm not sure about 2.4.
{ ... }@args:
let
  tests = import ./tests.nix args;
  inherit (tests) privatestorage lint-python;
  inherit (privatestorage) pkgs mach-nix tahoe-lafs zkapauthorizer;
  inherit (zkapauthorizer.meta.mach-nix) python providers;
  pythonPkg = pkgs.${python};

  python-env = mach-nix.mkPython {
    inherit python providers;
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

  # Unfortunately, the source archives.  Unpack them and use `directory ...`
  # in gdb to help it find them.
  SQLITE_SRC = "${pkgs.sqlite.src}";
  PYTHON_SRC = "${pythonPkg.src}";

  # Make pudb the default.
  PYTHONBREAKPOINT = "pudb.set_trace";

    # Supply all of the runtime and testing dependencies.
  buildInputs = [
    # If you download a non-broken libpython.py from cpython vcs you might get
    # useful commands like py-bt too.
    pkgs.gdb
    python-env

    # This could accidentally be the right bunch of debug symbols.  gdb seems
    # to find them on its own.  It needs help finding source files though.  It
    # would be nicer if we could pull the python version out of `python-env`
    # or `tests`.  Probably we can I'm not just not sure where it is.
    pythonPkg.debug
    pkgs.sqlite.debug
  ];
}
