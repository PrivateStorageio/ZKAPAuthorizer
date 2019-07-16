{ lib, buildPythonPackage, fetchFromGitHub, isPy3k,
  six, txaio, twisted, zope_interface, cffi, trollius, futures, cryptography,
  mock, pytest
}:
buildPythonPackage rec {
  pname = "autobahn";
  version = "19.7.1";

  src = fetchFromGitHub {
    owner = "crossbario";
    repo = "autobahn-python";
    rev = "v${version}";
    sha256 = "1gl2m18s77hlpiglh44plv3k6b965n66ylnxbzgvzcdl9jf3l3q3";
  };

  propagatedBuildInputs = [ six txaio twisted zope_interface cffi cryptography ] ++
    (lib.optionals (!isPy3k) [ trollius futures ]);

  checkInputs = [ mock pytest ];
  checkPhase = ''
    runHook preCheck
    USE_TWISTED=true py.test $out
    runHook postCheck
  '';

  # XXX Fails for some reason I don't understand.
  doCheck = false;

  meta = with lib; {
    description = "WebSocket and WAMP in Python for Twisted and asyncio.";
    homepage    = "https://crossbar.io/autobahn";
    license     = licenses.mit;
    maintainers = with maintainers; [ nand0p ];
  };
}
