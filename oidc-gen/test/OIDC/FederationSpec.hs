{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module OIDC.FederationSpec (spec) where

import Control.Lens ((&), (.~), (?~))
import Crypto.JWT (claimExp, claimIss, encodeCompact)
import qualified Data.ByteString.Lazy as LB
import Data.IORef
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Map.Strict as Map
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TE
import Data.Time (addUTCTime)
import OIDC
import OIDC.TestUtils
import Test.Syd

spec :: Spec
spec = do
  let refusalIn :: Outcome -> Maybe String
      refusalIn = \case
        Refused refusal -> Just (renderRefusal refusal)
        NotFederated -> Nothing
        Accepted _ -> Nothing

  let acceptedClaims :: Outcome -> Maybe Claims
      acceptedClaims = \case
        Accepted claims -> Just claims
        NotFederated -> Nothing
        Refused _ -> Nothing

  describe "verificationsByIssuer" $ do
    let forIssuer issuer = verificationFor (Issuer issuer) (Audience "a") (EdDSA :| [])

    it "keys the settings by the issuer each is about" $
      verificationsByIssuer [forIssuer "one", forIssuer "two"]
        `shouldBe` Right
          ( Map.fromList
              [ (Issuer "one", forIssuer "one"),
                (Issuer "two", forIssuer "two")
              ]
          )

    it "has no issuers at all for a service that federates with nobody" $
      verificationsByIssuer [] `shouldBe` Right Map.empty

    -- Only one of the two could ever be reached, and which one is an accident
    -- of the order they were written in.
    it "names an issuer that was configured twice" $
      verificationsByIssuer [forIssuer "one", forIssuer "two", forIssuer "one"]
        `shouldBe` Left (Issuer "one")

  describe "authenticate" $ do
    let verifications = Map.singleton (verificationIssuer aVerification) aVerification

    it "accepts a token one of its issuers signed" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      federation <- newFederation verifications
      (_, fetch) <- countedFetch (Just [publicKey])
      outcome <- authenticate (const fetch) federation aNow (LB.toStrict (encodeCompact token))
      fmap claimsSubject (acceptedClaims outcome) `shouldBe` Just "//example.com/sandbox/s1"

    -- A service that answered anything else here would be telling whoever
    -- asked which issuers it trusts.
    it "says nothing about a token from an issuer it does not federate with" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1"
            & claimIss ?~ aStringOrURI "https://elsewhere.example.com"
      federation <- newFederation verifications
      (asked, fetch) <- countedFetch (Just [publicKey])
      outcome <- authenticate (const fetch) federation aNow (LB.toStrict (encodeCompact token))
      outcome `shouldBe` NotFederated
      -- Nothing was checked, so nothing was fetched: an unknown issuer cannot
      -- be made to cost a request.
      readIORef asked `shouldReturn` 0

    it "says nothing about something that is not a token" $ do
      federation <- newFederation verifications
      (_, fetch) <- countedFetch (Just [])
      authenticate (const fetch) federation aNow "not a token at all"
        `shouldReturn` NotFederated

    it "says nothing at all when it federates with nobody" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      federation <- newFederation Map.empty
      (_, fetch) <- countedFetch (Just [publicKey])
      authenticate (const fetch) federation aNow (LB.toStrict (encodeCompact token))
        `shouldReturn` NotFederated

    it "refuses a token naming a key its issuer does not publish" $ do
      (key, _) <- generateEdDSAKeyPair
      other <- generateKeyNamed "another-key"
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      federation <- newFederation verifications
      (_, fetch) <- countedFetch (Just [other])
      outcome <- authenticate (const fetch) federation aNow (LB.toStrict (encodeCompact token))
      outcome `shouldBe` Refused (RefusalNamesUnknownKey "the-key")

    it "refuses a token when its issuer cannot be reached for keys" $ do
      (key, _) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      federation <- newFederation verifications
      (_, fetch) <- countedFetch Nothing
      outcome <- authenticate (const fetch) federation aNow (LB.toStrict (encodeCompact token))
      outcome `shouldBe` Refused (RefusalNamesUnknownKey "the-key")

    it "refuses a token its issuer signed but that says nothing valid" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1" & claimExp .~ Nothing
      federation <- newFederation verifications
      (_, fetch) <- countedFetch (Just [publicKey])
      outcome <- authenticate (const fetch) federation aNow (LB.toStrict (encodeCompact token))
      outcome `shouldBe` Refused RefusalHasNoLifetime

    -- The payload says which issuer to check against, and the rest of the
    -- token is what fails to decode, so this is the one way into that branch.
    it "refuses something naming one of its issuers that is not a signed JWT" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      payload <- case Text.splitOn "." (TE.decodeUtf8Lenient (LB.toStrict (encodeCompact token))) of
        [_, payload, _] -> pure payload
        _ -> expectationFailure "A signed token has three segments."
      federation <- newFederation verifications
      (_, fetch) <- countedFetch (Just [publicKey])
      outcome <-
        authenticate
          (const fetch)
          federation
          aNow
          (TE.encodeUtf8 (Text.intercalate "." ["!!!", payload, "!!!"]))
      refusalIn outcome `shouldBe` Just "the token is not a signed JWT: JWSError (JSONDecodeError \"Not valid base64url\")"

    -- A second refusal through the same branch, so that no single constant
    -- can stand in for the one the token was actually refused for.
    it "refuses an expired token its issuer signed" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      federation <- newFederation verifications
      (_, fetch) <- countedFetch (Just [publicKey])
      outcome <-
        authenticate (const fetch) federation (addUTCTime 3600 aNow) (LB.toStrict (encodeCompact token))
      refusalIn outcome `shouldBe` Just "the token does not verify: JWTExpired"

    it "refuses a token whose header names no key" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signTokenNamingNoKey key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      federation <- newFederation verifications
      (_, fetch) <- countedFetch (Just [publicKey])
      outcome <- authenticate (const fetch) federation aNow (LB.toStrict (encodeCompact token))
      outcome `shouldBe` Refused RefusalNamesNoKey

    -- One fetch for a hundred requests, and the keys stay held: the whole
    -- point of the key set being part of the federation rather than of a
    -- request.
    it "asks an issuer for its keys once across many tokens" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      federation <- newFederation verifications
      (asked, fetch) <- countedFetch (Just [publicKey])
      let bytes = LB.toStrict (encodeCompact token)
      _ <- authenticate (const fetch) federation aNow bytes
      _ <- authenticate (const fetch) federation aNow bytes
      _ <- authenticate (const fetch) federation aNow bytes
      readIORef asked `shouldReturn` 1
