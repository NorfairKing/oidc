{ mkDerivation, aeson, base, bytestring, containers, jose, lens
, lib, memory, text, time, unliftio, validity, validity-text
, validity-time
}:
mkDerivation {
  pname = "oidc";
  version = "0.0.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base bytestring containers jose lens memory text time
    unliftio validity validity-text validity-time
  ];
  homepage = "https://github.com/NorfairKing/oidc#readme";
  description = "Accept tokens from an OpenID Connect issuer";
  license = lib.licenses.unfree;
  hydraPlatforms = lib.platforms.none;
}
