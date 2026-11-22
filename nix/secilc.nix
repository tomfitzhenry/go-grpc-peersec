{
  lib,
  stdenv,
  fetchurl,
  libsepol,
}:

stdenv.mkDerivation {
  pname = "secilc";
  inherit (libsepol) version;

  src = fetchurl {
    url = "${libsepol.se_url}/${libsepol.version}/secilc-${libsepol.version}.tar.gz";
    hash = "sha256-ZlgHHW8QRBhNOXMGKnmBh1N64cPdtMMa/UF98zMxbBA=";
  };

  buildInputs = [ libsepol ];

  # Build only the compiler binary; the default target also builds man pages
  # via xmlto/docbook, which we do not need.
  buildFlags = [ "secilc" ];

  installPhase = ''
    runHook preInstall
    install -Dm755 secilc "$out/bin/secilc"
    runHook postInstall
  '';

  meta = {
    description = "SELinux Common Intermediate Language (CIL) compiler";
    homepage = "https://github.com/SELinuxProject/selinux";
    license = lib.licenses.bsd2;
    mainProgram = "secilc";
    platforms = lib.platforms.linux;
  };
}
