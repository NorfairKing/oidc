{ mkDerivation, aeson, base, bytestring, containers, genvalidity
, genvalidity-sydtest, genvalidity-text, genvalidity-time, jose
, lens, lib, oidc, QuickCheck, sydtest, sydtest-discover, text
, time
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
    aeson base bytestring containers genvalidity-sydtest jose lens oidc
    sydtest text time
  ];
  testToolDepends = [ sydtest-discover ];
  homepage = "https://github.com/NorfairKing/oidc#readme";
  description = "Generators and test utilities for oidc";
  license = lib.licenses.mit;
}
