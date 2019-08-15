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
    # HEAD of integration/storage-economics branch as of July 15th 2019.
    rev = "b35a8908f4096ccae35da78b0e7dde96d6cf1667";
    sha256 = "0n289hzx2s1jvspmpz2c5iwl0dvnfc8qbiqfmpbl88ymrjp7p6rr";
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
