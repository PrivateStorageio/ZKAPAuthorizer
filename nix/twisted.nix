{twisted, fetchPypi, lib}:
twisted.overrideAttrs (old: {
    # XXX name or version metadata is wrong
    src = fetchPypi {
      pname = "Twisted";
      version = "22.10.0";
      sha256 = "sha256-Mqy9QKlPX0bntCwQm/riswIlCUVWF4Oot6BZBI8tTTE=";
    };
})