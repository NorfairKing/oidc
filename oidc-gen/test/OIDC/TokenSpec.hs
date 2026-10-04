{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module OIDC.TokenSpec (spec) where

import Control.Lens ((&), (.~), (?~))
import Control.Monad (void)
import Crypto.JOSE.Header (HeaderParam (..), kid)
import Crypto.JWT
  ( JWTError (..),
    NumericDate (..),
    claimAud,
    claimExp,
    claimIat,
    claimIss,
    claimJti,
    claimSub,
    encodeCompact,
    newJWSHeader,
    runJOSE,
    signClaims,
    signJWT,
  )
import qualified Crypto.JWT as JWT
import qualified Data.Aeson as JSON
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteString.Lazy as LB
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.Map.Strict as Map
import Data.Time
import OIDC
import OIDC.TestUtils
import Test.Syd

spec :: Spec
spec = do
  -- Rendered rather than compared as a value, so that a test says why a token
  -- was refused and forces the reason rather than only the shape of it.
  let refusalFor :: Either Refusal a -> Maybe String
      refusalFor = \case
        Left refusal -> Just (renderRefusal refusal)
        Right _ -> Nothing

  describe "unverifiedIssuer" $ do
    it "reads the issuer a token names" $ do
      (key, _) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "whoever")
      unverifiedIssuer (LB.toStrict (encodeCompact token))
        `shouldBe` Just (Issuer "https://sts.example.com")

    it "reads no issuer out of something that is not a token" $
      unverifiedIssuer "not a token at all" `shouldBe` Nothing

    it "reads no issuer out of a token whose payload is not base64" $
      unverifiedIssuer "aaaa.!!!!.cccc" `shouldBe` Nothing

    it "reads no issuer out of a token that names none" $ do
      (key, _) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "whoever" & claimIss .~ Nothing)
      unverifiedIssuer (LB.toStrict (encodeCompact token)) `shouldBe` Nothing

  describe "renderRefusal" $
    -- A refusal is only ever told to whoever configured the issuer, so this
    -- is the whole of what they are told about a token that was turned away.
    -- Spelled out rather than checked for a word each, because a sentence
    -- with a phrase missing still holds the word.
    it "says what each refusal is" $
      map
        renderRefusal
        [ RefusalMalformed "the reason",
          RefusalNamesNoKey,
          RefusalNamesUnknownKey "the-key",
          RefusalDoesNotVerify JWTExpired,
          RefusalHasNoIssuer,
          RefusalHasNoAudience,
          RefusalHasNoLifetime,
          RefusalLivesTooLong 86400 300,
          RefusalHasNoSubject
        ]
        `shouldBe` [ "the token is not a signed JWT: the reason",
                     "the token's header names no key, so it cannot say which of the issuer's keys signed it",
                     "the token names the key \"the-key\", which the issuer does not publish",
                     "the token does not verify: JWTExpired",
                     "the token names no issuer, so nothing says who signed it",
                     "the token says no audience, so nobody said it was for this service",
                     "the token does not say when it was issued and when it expires, so it is not short-lived",
                     "the token lives for 86400s but this issuer's tokens may live for at most 300s",
                     "the token has no subject, so nothing can be said about who it is"
                   ]

  describe "verifyToken" $ do
    it "accepts a token signed with the issuer's EdDSA key" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      verifyToken aVerification publicKey aNow token
        `shouldBe` Right
          Claims
            { claimsIssuer = Issuer "https://sts.example.com",
              claimsSubject = "//example.com/sandbox/s1",
              claimsAudiences = [Audience "the-service"],
              claimsId = Nothing,
              claimsIssuedAt = aNow,
              claimsExpiry = addUTCTime 300 aNow,
              claimsAll =
                Map.fromList
                  [ ("iss", JSON.String "https://sts.example.com"),
                    ("aud", JSON.String "the-service"),
                    ("sub", JSON.String "//example.com/sandbox/s1"),
                    ("iat", JSON.Number 1791028800),
                    ("exp", JSON.Number 1791029100)
                  ]
            }

    it "accepts a token signed with the issuer's RSA key" $ do
      (key, publicKey) <- generateRSAKeyPair
      token <- signToken key RS256 (aClaimsSet "//example.com/sandbox/s1")
      fmap claimsSubject (verifyToken aVerification publicKey aNow token)
        `shouldBe` Right "//example.com/sandbox/s1"

    -- The token id is the only thing that tells two tokens of one workload
    -- apart, since everything else about them is the same.
    it "says which token it accepted, where the issuer names one" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1" & claimJti ?~ "the-token"
      fmap claimsId (verifyToken aVerification publicKey aNow token)
        `shouldBe` Right (Just "the-token")

    it "says every audience the token was minted for" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1"
            & claimAud ?~ JWT.Audience [aStringOrURI "the-service", aStringOrURI "something-else"]
      fmap claimsAudiences (verifyToken aVerification publicKey aNow token)
        `shouldBe` Right [Audience "the-service", Audience "something-else"]

    it "hands back every claim at the top level of the payload" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      -- Signed from the payload an issuer would send, rather than through
      -- jose's claims set, because a claim beside the registered ones is
      -- exactly what jose's own payload type has no room for.
      let payload = case JSON.toJSON (aClaimsSet "//example.com/sandbox/s1") of
            JSON.Object object -> JSON.Object (KeyMap.insert "client_id" (JSON.String "repl") object)
            other -> other
      errOrToken <-
        runJOSE $
          signJWT key (newJWSHeader ((), algorithmJoseAlg EdDSA) & kid ?~ HeaderParam () aKid) payload
      token <- case errOrToken of
        Left (err :: JWTError) -> expectationFailure (show err)
        Right token -> pure token
      fmap (Map.lookup "client_id" . claimsAll) (verifyToken aVerification publicKey aNow token)
        `shouldBe` Right (Just (JSON.String "repl"))

    it "refuses a token from another issuer" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1"
            & claimIss ?~ aStringOrURI "https://elsewhere.example.com"
      refusalFor (verifyToken aVerification publicKey aNow token)
        `shouldBe` Just "the token does not verify: JWTNotInIssuer"

    it "refuses a token minted for another audience" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1"
            & claimAud ?~ JWT.Audience [aStringOrURI "somewhere-else"]
      refusalFor (verifyToken aVerification publicKey aNow token)
        `shouldBe` Just "the token does not verify: JWTNotInAudience"

    -- jose asks each of its predicates only about a claim the token carries,
    -- so these two are the checks it does not make for us.
    it "refuses a token that names no issuer" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1" & claimIss .~ Nothing
      verifyToken aVerification publicKey aNow token `shouldBe` Left RefusalHasNoIssuer

    it "refuses a token minted for nobody in particular" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1" & claimAud .~ Nothing
      verifyToken aVerification publicKey aNow token `shouldBe` Left RefusalHasNoAudience

    it "refuses an expired token" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      refusalFor (verifyToken aVerification publicKey (addUTCTime 3600 aNow) token)
        `shouldBe` Just "the token does not verify: JWTExpired"

    it "refuses a token issued in the future" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      refusalFor (verifyToken aVerification publicKey (addUTCTime (-3600) aNow) token)
        `shouldBe` Just "the token does not verify: JWTIssuedAtFuture"

    -- The skew is what makes the two tests above about a clock that is wrong
    -- rather than about a clock that is a second out.
    it "accepts a token that expired within the clock skew" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      fmap claimsSubject (verifyToken aVerification publicKey (addUTCTime 330 aNow) token)
        `shouldBe` Right "//example.com/sandbox/s1"

    it "refuses a token that lives longer than the issuer is allowed" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1"
            & claimExp ?~ NumericDate (addUTCTime 86400 aNow)
      verifyToken aVerification publicKey aNow token
        `shouldBe` Left (RefusalLivesTooLong 86400 300)

    it "accepts a token that lives exactly as long as the issuer is allowed" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      fmap claimsSubject (verifyToken aVerification publicKey aNow token)
        `shouldBe` Right "//example.com/sandbox/s1"

    -- An issuer whose lifetimes are not bounded here is an issuer trusted to
    -- choose them, which is the only thing a caller that sets no maximum can
    -- mean.
    it "accepts a long-lived token from an issuer with no maximum lifetime" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1"
            & claimExp ?~ NumericDate (addUTCTime 86400 aNow)
      fmap
        claimsSubject
        ( verifyToken
            aVerification {verificationMaxTokenLifetime = Nothing}
            publicKey
            aNow
            token
        )
        `shouldBe` Right "//example.com/sandbox/s1"

    it "refuses a token that never expires" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1" & claimExp .~ Nothing
      verifyToken aVerification publicKey aNow token `shouldBe` Left RefusalHasNoLifetime

    it "refuses a token that does not say when it was issued" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1" & claimIat .~ Nothing
      verifyToken aVerification publicKey aNow token `shouldBe` Left RefusalHasNoLifetime

    -- A token that expires the moment it is issued is degenerate but
    -- well-formed: it says how long it lives, and that is no time at all.
    -- Where the line sits is what tells it from the one below.
    it "accepts a token that expires the moment it was issued" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1" & claimExp ?~ NumericDate aNow
      fmap claimsLifetime (verifyToken aVerification publicKey aNow token) `shouldBe` Right 0

    it "refuses a token that expired before it was issued" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1"
            & claimExp ?~ NumericDate (addUTCTime (-1) aNow)
      verifyToken aVerification publicKey aNow token `shouldBe` Left RefusalHasNoLifetime

    it "refuses a token signed with an algorithm the issuer does not use" $ do
      (key, publicKey) <- generateRSAKeyPair
      token <- signToken key PS256 (aClaimsSet "//example.com/sandbox/s1")
      refusalFor
        ( verifyToken
            aVerification {verificationAlgorithms = RS256 :| []}
            publicKey
            aNow
            token
        )
        `shouldBe` Just "the token does not verify: JWSError JWSNoSignatures"

    it "refuses a token signed with another key" $ do
      (key, _) <- generateEdDSAKeyPair
      (_, otherPublicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      refusalFor (verifyToken aVerification otherPublicKey aNow token)
        `shouldBe` Just "the token does not verify: JWSError JWSInvalidSignature"

    it "refuses a token with no subject at all" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <-
        signToken key EdDSA $
          aClaimsSet "//example.com/sandbox/s1" & claimSub .~ Nothing
      verifyToken aVerification publicKey aNow token `shouldBe` Left RefusalHasNoSubject

  describe "claimsLifetime" $
    it "is the time between a token being issued and expiring" $ do
      (key, publicKey) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "//example.com/sandbox/s1")
      fmap claimsLifetime (verifyToken aVerification publicKey aNow token) `shouldBe` Right 300

  describe "decodeToken" $ do
    it "reads a token the issuer signed" $ do
      (key, _) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "whoever")
      fmap tokenKid (decodeToken (LB.toStrict (encodeCompact token)))
        `shouldBe` Right (Just aKid)

    it "says what is wrong with something that is not a token" $
      void (decodeToken "not a token at all")
        `shouldBe` Left (RefusalMalformed "JWSError (CompactDecodeError Invalid number of parts: Expected 3 parts; got 1)")

  describe "tokenKid" $ do
    it "reads the key a token names" $ do
      (key, _) <- generateEdDSAKeyPair
      token <- signToken key EdDSA (aClaimsSet "whoever")
      tokenKid token `shouldBe` Just aKid

    it "reads no key out of a token that names none" $ do
      (key, _) <- generateEdDSAKeyPair
      errOrToken <- runJOSE (signClaims key (newJWSHeader ((), algorithmJoseAlg EdDSA)) (aClaimsSet "whoever"))
      token <- case errOrToken of
        Left (err :: JWTError) -> expectationFailure (show err)
        Right token -> pure token
      tokenKid token `shouldBe` Nothing

-- | The instant every test here checks its tokens against.
