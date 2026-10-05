{ mkDerivation, aeson, autodocodec, base, bytestring, containers
, genvalidity, genvalidity-sydtest, genvalidity-sydtest-aeson
, genvalidity-text, genvalidity-time, jose, lens, lib, oidc
, QuickCheck, sydtest, sydtest-discover, text, time, unliftio
}:
mkDerivation {
  pname = "oidc-gen";
  version = "0.0.0.0";
  src = ./.;
  libraryHaskellDepends = [
    base genvalidity genvalidity-text genvalidity-time jose lens oidc
    QuickCheck sydtest text time
  ];
  testHaskellDepends = [
    aeson autodocodec base bytestring containers genvalidity-sydtest
    genvalidity-sydtest-aeson jose lens oidc sydtest text time unliftio
  ];
  testToolDepends = [ sydtest-discover ];
  homepage = "https://github.com/NorfairKing/oidc#readme";
  description = "Generators and test utilities for oidc";
  license = lib.licenses.unfree;
  hydraPlatforms = lib.platforms.none;
}
