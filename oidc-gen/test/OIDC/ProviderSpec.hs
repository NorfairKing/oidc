{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module OIDC.ProviderSpec (spec) where

import Data.List.NonEmpty (NonEmpty (..))
import OIDC
import OIDC.Gen ()
import Test.Syd
import Test.Syd.Validity

spec :: Spec
spec = do
  genValidSpec @Issuer
  genValidSpec @Audience
  genValidSpec @Verification

  describe "verificationFor" $ do
    it "accepts only the issuer and audience it was given" $
      verificationFor (Issuer "https://sts.example.com") (Audience "the-service") (EdDSA :| [])
        `shouldBe` Verification
          { verificationIssuer = Issuer "https://sts.example.com",
            verificationAudiences = Audience "the-service" :| [],
            verificationAlgorithms = EdDSA :| [],
            verificationMaxTokenLifetime = Nothing,
            verificationClockSkew = 0
          }

    it "is valid" $
      forAllValid $ \issuer ->
        forAllValid $ \audience ->
          forAllValid $ \algorithms ->
            shouldBeValid (verificationFor issuer audience algorithms)

  -- A maximum lifetime of no time at all would refuse every token there is,
  -- and a negative skew would refuse every clock, so neither is a
  -- configuration anybody can hold. Asserted here because generating only
  -- valid values never asks whether an invalid one is caught.
  describe "Validity Verification" $ do
    let aVerification = verificationFor (Issuer "i") (Audience "a") (EdDSA :| [])

    it "is invalid with a negative clock skew" $
      shouldBeInvalid aVerification {verificationClockSkew = -1}

    it "is valid with no clock skew at all" $
      shouldBeValid aVerification {verificationClockSkew = 0}

    it "is invalid with a maximum token lifetime of no time at all" $
      shouldBeInvalid aVerification {verificationMaxTokenLifetime = Just 0}

    it "is invalid with a negative maximum token lifetime" $
      shouldBeInvalid aVerification {verificationMaxTokenLifetime = Just (-1)}

    it "is valid with a positive maximum token lifetime" $
      shouldBeValid aVerification {verificationMaxTokenLifetime = Just 1}

    it "is valid with no maximum token lifetime at all" $
      shouldBeValid aVerification {verificationMaxTokenLifetime = Nothing}
