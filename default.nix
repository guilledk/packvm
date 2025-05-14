{ pkgs ? import <nixpkgs> {} }:
let
  nativeBuildInputs = with pkgs; [
    openssl pkg-config
    stdenv.cc.cc.lib
    uv
  ];
  python-deriv = pkgs.python312;

in
pkgs.mkShell {
  inherit nativeBuildInputs;

  CPYTHON_INCLUDE_PATH = "${python-deriv}/include/python3.12";
  LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath nativeBuildInputs;
  TMPDIR = "/tmp";
}
