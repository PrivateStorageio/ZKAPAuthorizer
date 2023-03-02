# A basic packaging of this very project: Python bindings to the Rust
# Ristretto implementation.
{ libchallenge_bypass_ristretto_ffi, python, pythonPackages, milksnake, cffi, attrs, testtools, hypothesis }:
pythonPackages.buildPythonPackage rec {
  version = "2022.6.30";
  pname = "python-challenge-bypass-ristretto";
  name = "${pname}-${version}";
  src = ../.;

  # We hack up setup.py a bit.  We're going to supply a pre-built Ristretto
  # FFI library.  We don't want Python distutils to build it for us.  This
  # gives us more control and is easier than trying to mash Python and Rust
  # build environments into one.
  postUnpack = ''
  substituteInPlace $sourceRoot/setup.py \
      --replace "['cargo', 'build', '--release']" "['sh', '-c', ':']" \
      --replace "./challenge-bypass-ristretto-ffi" "/" \
      --replace "target/release" "${libchallenge_bypass_ristretto_ffi}/lib" \
      --replace "./src" "${libchallenge_bypass_ristretto_ffi.src}/src" \
      --replace "'setuptools_scm'" ""
  '';

  propagatedNativeBuildInputs = [
    libchallenge_bypass_ristretto_ffi
  ];

  propagatedBuildInputs = [
    # the bindings are cffi-based
    cffi
    attrs
  ];

  buildInputs = [
    # required to build the cffi extension module
    milksnake
  ];

  checkInputs = [
    testtools
    hypothesis
  ];
}
