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
