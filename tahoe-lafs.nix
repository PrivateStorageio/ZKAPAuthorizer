{ fetchFromGitHub, nettools, pythonPackages, buildPythonPackage, eliot, autobahn }:
buildPythonPackage rec {
  version = "1.14.0.dev";
  name = "tahoe-lafs-${version}";
  src = fetchFromGitHub {
    owner = "tahoe-lafs";
    repo = "tahoe-lafs";
    # HEAD of integration/storage-economics branch as of July 15th 2019.
    rev = "48bd16a8d9109910122cc2e2c85eb4f378390135";
    sha256 = "0i8k7zb4381vbblriciz1m33va0mxld6nrhpwvjqr9jk335b1a9q";
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
    twisted autobahn foolscap nevow simplejson zfec pycryptopp darcsver
    setuptoolsTrial setuptoolsDarcs pycrypto pyasn1 zope_interface
    service-identity pyyaml magic-wormhole treq appdirs

    eliot
  ];

  doCheck = false;
}
