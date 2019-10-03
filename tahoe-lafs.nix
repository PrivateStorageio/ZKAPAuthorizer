{ fetchFromGitHub, nettools, pythonPackages, buildPythonPackage
, twisted, foolscap, nevow, simplejson, zfec, pycryptopp, darcsver
, setuptoolsTrial, setuptoolsDarcs, pycrypto, pyasn1, zope_interface
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
    # updated August 23 2019.
    rev = "d4b5de2e08e26ad2cc14265a5993be2ecc791d5b";
    sha256 = "1l2da13w43zzwr1z262zhhq4hq3sha4zrxp7d46zmjn4ya0ixksf";
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
    sed -i 's/"pycrypto.*"/"pycrypto"/' src/allmydata/_auto_deps.py
  '';


  propagatedBuildInputs = with pythonPackages; [
    twisted foolscap nevow simplejson zfec pycryptopp darcsver
    setuptoolsTrial setuptoolsDarcs pycrypto pyasn1 zope_interface
    service-identity pyyaml magic-wormhole treq appdirs

    eliot autobahn
  ];

  doCheck = false;
}
