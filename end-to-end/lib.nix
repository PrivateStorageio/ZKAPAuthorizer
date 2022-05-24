{ pkgs, ... }:
rec {
  /* Returns a string that runs tests from the Python code at the given path.

     The Python code is loaded using *execfile* and the *test* global it
     defines is called with the given keyword arguments.

     Type: makeTestScript :: Path -> AttrSet -> String

     Example:
       testScript = (makeTestScript ./test_foo.py { x = "y"; });
  */
  makeTestScript = { testpath, kwargs ? {} }:
    ''
    # The driver runs pyflakes on this script before letting it
    # run... Convince pyflakes that there is a `test` name.
    test = None
    with open("${testpath}") as testfile:
        exec(testfile.read(), globals())
    # For simple types, JSON is compatible with Python syntax!
    test(**${builtins.toJSON kwargs})
    '';

  /* Return a NixOS configuration for a VM which will run a Tahoe-LAFS client
     node with ZKAPAuthorizer installed on it.

     The argument is a package to use to get Tahoe-LAFS and ZKAPAuthorizer.
  */
  client = { zkapauthorizer }:
    { config, pkgs, ... }:
    {
      disabledModules = [ "services/network-filesystems/tahoe.nix" ];
      imports = [
        ./tahoe-lafs/default.nix
      ];

      services.tahoe = {
        # nodes.c.package = zkapauthorizer;
        nodes.c.settings = {
          node.nickname = "client";
          client."introducer.furl" = builtins.readFile (introducer.furlFile {
            hostname = "introducer";
            portNumber = 12345;
          });
        };
      };
    };

  /* Return a NixOS configuration for a VM which will run a Tahoe-LAFS
     introducer and storage node with ZKAPAuthorizer installed on it.

     The argument is a package to use to get Tahoe-LAFS and ZKAPAuthorizer.
  */
  server = { zkapauthorizer }:
    { config, pkgs, ... }:
    {
      disabledModules = [ "services/network-filesystems/tahoe.nix" ];
      imports = [
        ./tahoe-lafs/default.nix
      ];

      services.tahoe = {
        introducers.i = {
          # package = zkapauthorizer;
          nickname = "introducer";
        };
        # nodes.s.package = zkapauthorizer;
        nodes.s.settings = {
          node.nickname = "storage";
          storage.enable = true;
          client."introducer.furl" = builtins.readFile (introducer.furlFile {
            hostname = "introducer";
            portNumber = 12345;
          });
        };
      };
    };

  /* Details about an introducer.  The fURL is hard-coded to match secrets
     used by the introducer created by ``server`` above.
   */
  introducer = rec {
    tubID = "rr7y46ixsg6qmck4jkkc7hke6xe4sv5f";
    swissnum = "2k6p3wrabat5jrj7otcih4cjdema4q3m";

    /* A store file that can be used as an "introducer.furl" file for a
       Tahoe-LAFS node.
     */
    furlFile = { hostname, portNumber }:
      let
        location = "tcp:${hostname}:${toString portNumber}";
        introducerFURL = "pb://${tubID}@${location}/${swissnum}";
      in
        pkgs.writeTextFile {
          name = "introducer.furl";
          text = introducerFURL;
        };
  };
}
