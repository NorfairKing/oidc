{ mkDerivation, aeson, base, bytestring, http-client, http-types
, lib, network-uri, oidc, opt-env-conf, sydtest, text, time
}:
mkDerivation {
  pname = "oidc-e2e";
  version = "0.0.0.0";
  src = ./.;
  isLibrary = true;
  isExecutable = true;
  libraryHaskellDepends = [
    aeson base bytestring http-client http-types network-uri oidc
    opt-env-conf sydtest text time
  ];
  executableHaskellDepends = [ base ];
  description = "End-to-end tests for oidc against a real issuer";
  license = lib.licenses.unfree;
  hydraPlatforms = lib.platforms.none;
  mainProgram = "oidc-e2e";
}
