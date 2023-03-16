{ pythonPackages, buildPythonPackage, tahoe-lafs-version, tahoe-lafs-src, postPatch }:
buildPythonPackage rec {
  pname = "tahoe-lafs";
  version = tahoe-lafs-version;
  src = tahoe-lafs.src;

  inherit postPatch;

  dontUseSetuptoolsCheck = true;
  propagatedBuildInputs = with pythonPackages; [
    zfec
    zope_interface
    foolscap
    cryptography
    twisted
    pyyaml
    six
    magic-wormhole
    eliot
    pyrsistent
    attrs
    autobahn
    future
    netifaces
    pyutil
    collections-extended
    klein
    werkzeug
    treq
    cbor2
    pycddl
    click
    psutil
    filelock
    distro
    appdirs
    bcrypt
    aniso8601
  ];
}
