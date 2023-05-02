{ lib, pythonPackages, buildPythonPackage, tahoe-lafs-version, tahoe-lafs-src, postPatch }:
buildPythonPackage {
  pname = "tahoe-lafs";
  version = tahoe-lafs-version;
  src = tahoe-lafs-src;

  postPatch =
    (if postPatch == null then "" else postPatch) +
    # This < is really trying to be a !=.  We provide a new-enough Autobahn
    # that it actually works, so remove the constraint from the Python metadata.
    ''
      sed -i -e "s/autobahn < 22.4.1/autobahn/" setup.py
    '';

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
