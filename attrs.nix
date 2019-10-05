{ lib, stdenv, buildPythonPackage, fetchPypi, pytest, hypothesis, zope_interface
, pympler, coverage, six, clang }:

buildPythonPackage rec {
  pname = "attrs";
  version = "19.2.0";

  src = fetchPypi {
    inherit pname version;
    sha256 = "sha256:15hkbvwzw87474ra22mmzbbikkqkrnk9npifa1pw7lv32qp4j4zr";
  };

  # macOS needs clang for testing
  checkInputs = [
    pytest hypothesis zope_interface pympler coverage six
  ] ++ lib.optionals (stdenv.isDarwin) [ clang ];

  checkPhase = ''
    py.test
  '';

  # To prevent infinite recursion with pytest
  doCheck = false;

  meta = with lib; {
    description = "Python attributes without boilerplate";
    homepage = https://github.com/hynek/attrs;
    license = licenses.mit;
  };
}
