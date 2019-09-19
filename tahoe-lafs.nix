{ fetchFromGitHub, nettools, pythonPackages, buildPythonPackage
, twisted, foolscap, nevow, simplejson, zfec, pycryptopp, darcsver
, setuptoolsTrial, setuptoolsDarcs, pyasn1, zope_interface, cryptography
, service-identity, pyyaml, magic-wormhole, treq, appdirs
, eliot, autobahn
}:
buildPythonPackage rec {
  version = "1.14.0.dev";
  name = "tahoe-lafs-${version}";
  src = fetchFromGitHub {
    owner = "LeastAuthority";
    repo = "tahoe-lafs";
    # HEAD of an integration branch for all of the storage plugin stuff.  Last
    # updated August 20th 2019.
    rev = "ba2f31f5f3719c7cf9f621852571e89ab445bf61";
    sha256 = "02c3zghx1951zw1912c2qf9s7n41wsbz8ld5700myak69nvkh0gs";
  };

  postPatch = ''
    sed -i "src/allmydata/util/iputil.py" \
        -es"|_linux_path = '/sbin/ifconfig'|_linux_path = '${nettools}/bin/ifconfig'|g"

    # Chroots don't have /etc/hosts and /etc/resolv.conf, so work around
    # that.
    for i in $(find src/allmydata/test -type f)
    do
      sed -i "$i" -e"s/localhost/127.0.0.1/g"
    done

    sed -i 's/"zope.interface.*"/"zope.interface"/' src/allmydata/_auto_deps.py
  '';


  propagatedBuildInputs = with pythonPackages; [
    twisted foolscap nevow simplejson zfec pycryptopp darcsver
    setuptoolsTrial setuptoolsDarcs pyasn1 zope_interface
    service-identity pyyaml magic-wormhole treq appdirs

    eliot autobahn cryptography
  ];

  doCheck = false;
}
