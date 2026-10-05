{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module OIDC.ProviderSpec (spec) where

import Autodocodec (eitherDecodeJSONViaCodec, toJSONViaCodec)
import qualified Data.Aeson as JSON
import Data.List.NonEmpty (NonEmpty (..))
import OIDC
import OIDC.Gen ()
import Test.Syd
import Test.Syd.Validity

spec :: Spec
spec = do
  genValidSpec @Issuer
  genValidSpec @TokenAudience
  genValidSpec @Verification

  describe "the Issuer and TokenAudience codecs" $ do
    it "reads back an issuer it wrote" $
      forAllValid $ \issuer ->
        eitherDecodeJSONViaCodec (JSON.encode (toJSONViaCodec issuer))
          `shouldBe` Right (issuer :: Issuer)

    it "writes an issuer as the text it is" $
      forAllValid $ \issuer ->
        toJSONViaCodec issuer `shouldBe` JSON.String (unIssuer issuer)

    it "reads back an audience it wrote" $
      forAllValid $ \audience ->
        eitherDecodeJSONViaCodec (JSON.encode (toJSONViaCodec audience))
          `shouldBe` Right (audience :: TokenAudience)

    it "writes an audience as the text it is" $
      forAllValid $ \audience ->
        toJSONViaCodec audience `shouldBe` JSON.String (unTokenAudience audience)

  describe "verificationFor" $ do
    it "accepts only the issuer and audience it was given" $
      verificationFor (Issuer "https://sts.example.com") (TokenAudience "the-service") (EdDSA :| [])
        `shouldBe` Verification
          { verificationIssuer = Issuer "https://sts.example.com",
            verificationAudiences = TokenAudience "the-service" :| [],
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
    let aVerification = verificationFor (Issuer "i") (TokenAudience "a") (EdDSA :| [])

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
