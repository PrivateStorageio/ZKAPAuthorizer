{ buildPythonPackage, sphinx, circleci-cli
, attrs, zope_interface, twisted, tahoe-lafs
, fixtures, testtools, hypothesis, pyflakes, treq, coverage
}:
buildPythonPackage rec {
  version = "0.0";
  pname = "zero-knowledge-access-pass-authorizer";
  name = "${pname}-${version}";
  src = ./.;

  outputs = [ "out" "doc" ];

  depsBuildBuild = [
    sphinx
    circleci-cli
  ];

  propagatedBuildInputs = [
    attrs
    zope_interface
    twisted
    tahoe-lafs
  ];

  checkInputs = [
    coverage
    fixtures
    testtools
    hypothesis
    twisted
    treq
  ];

  checkPhase = ''
    runHook preCheck
    "${pyflakes}/bin/pyflakes" src/_zkapauthorizer
    python -m coverage run --branch --source _zkapauthorizer,twisted.plugins.zkapauthorizer --module twisted.trial _zkapauthorizer
    runHook postCheck
  '';

  postCheck = ''
    python -m coverage html
    mkdir -p "$doc/share/doc/${name}"
    cp -vr .coverage htmlcov "$doc/share/doc/${name}"
  '';
}
