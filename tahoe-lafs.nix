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
    rev = "e7bd717a3f1dc89e81df583fca177bb3d92ebfa2";
    sha256 = "0s5w9r1zmagl16ig6642wn8dcpkwb6qn4816xbrzh1d7y3pr11rd";
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
