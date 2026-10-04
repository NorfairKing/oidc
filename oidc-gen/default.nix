{ mkDerivation, aeson, base, bytestring, containers, genvalidity
, genvalidity-sydtest, genvalidity-text, genvalidity-time, jose
, lens, lib, oidc, QuickCheck, sydtest, text, time, unliftio
}:
mkDerivation {
  pname = "oidc-gen";
  version = "0.0.0";
  src = ./.;
  libraryHaskellDepends = [
    base containers genvalidity genvalidity-text genvalidity-time oidc
    QuickCheck text time
  ];
  testHaskellDepends = [
    aeson base bytestring containers genvalidity-sydtest jose lens oidc
    QuickCheck sydtest text time unliftio
  ];
  description = "Generators and tests for oidc";
  license = lib.licenses.mit;
}
