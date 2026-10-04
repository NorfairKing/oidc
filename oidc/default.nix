{ mkDerivation, aeson, base, bytestring, containers, jose, lens
, lib, memory, text, time, unliftio, validity, validity-text
, validity-time
}:
mkDerivation {
  pname = "oidc";
  version = "0.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base bytestring containers jose lens memory text time
    unliftio validity validity-text validity-time
  ];
  description = "Accept tokens from an OpenID Connect issuer";
  license = lib.licenses.mit;
}
