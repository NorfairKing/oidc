{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | What more than one spec needs to have in front of it before it can ask a
-- question: keys, tokens signed with them, and an issuer to check them
-- against.
module OIDC.TestUtils
  ( aNow,
    aKid,
    aStringOrURI,
    aVerification,
    aClaimsSet,
    signToken,
    signTokenNamingNoKey,
    generateEdDSAKeyPair,
    generateRSAKeyPair,
    generateKeyNamed,
    countedFetch,
  )
where

import Control.Lens (set, view, (&), (?~))
import Crypto.JOSE.Header (HeaderParam (..), kid)
import Crypto.JOSE.JWK (JWK, KeyMaterialGenParam (..), OKPCrv (..), asPublicKey, genJWK, jwkKid)
import Crypto.JWT
  ( ClaimsSet,
    JWTError,
    NumericDate (..),
    SignedJWT,
    StringOrURI,
    claimAud,
    claimExp,
    claimIat,
    claimIss,
    claimSub,
    emptyClaimsSet,
    newJWSHeader,
    runJOSE,
    signClaims,
  )
import qualified Crypto.JWT as JWT
import Data.IORef
import Data.List.NonEmpty (NonEmpty (..))
import Data.String (fromString)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Time
import OIDC
import Test.Syd

-- | The instant every token in these tests is checked against.
--
-- Fixed rather than read from the clock, so that a test which passes does so
-- for the reason it says and not because of when it ran.
aNow :: UTCTime
aNow = UTCTime (fromGregorian 2026 10 3) (secondsToDiffTime (12 * 3600))

aKid :: Text
aKid = "the-key"

-- | A text as a registered claim holds it.
aStringOrURI :: Text -> StringOrURI
aStringOrURI = fromString . Text.unpack

aVerification :: Verification
aVerification =
  Verification
    { verificationIssuer = Issuer "https://sts.example.com",
      verificationAudiences = Audience "the-service" :| [],
      verificationAlgorithms = EdDSA :| [RS256],
      verificationMaxTokenLifetime = Just 300,
      verificationClockSkew = 60
    }

-- | A token 'aVerification''s issuer would mint: for this service, now, and
-- about a subject.
aClaimsSet :: Text -> ClaimsSet
aClaimsSet subject =
  emptyClaimsSet
    & claimIss ?~ aStringOrURI "https://sts.example.com"
    & claimAud ?~ JWT.Audience [aStringOrURI "the-service"]
    & claimSub ?~ aStringOrURI subject
    & claimIat ?~ NumericDate aNow
    & claimExp ?~ NumericDate (addUTCTime 300 aNow)

signToken :: JWK -> Algorithm -> ClaimsSet -> IO SignedJWT
signToken key algorithm claims = do
  errOrToken <-
    runJOSE $
      signClaims
        key
        (newJWSHeader ((), algorithmJoseAlg algorithm) & kid ?~ HeaderParam () aKid)
        claims
  case errOrToken of
    Left (err :: JWTError) -> expectationFailure (show err)
    Right token -> pure token

-- | A token whose header says nothing about which key signed it.
signTokenNamingNoKey :: JWK -> Algorithm -> ClaimsSet -> IO SignedJWT
signTokenNamingNoKey key algorithm claims = do
  errOrToken <-
    runJOSE (signClaims key (newJWSHeader ((), algorithmJoseAlg algorithm)) claims)
  case errOrToken of
    Left (err :: JWTError) -> expectationFailure (show err)
    Right token -> pure token

-- | A key pair, and the half of it an issuer publishes, which is all a
-- resource server ever holds.
generateEdDSAKeyPair :: IO (JWK, JWK)
generateEdDSAKeyPair = keyPairOf (OKPGenParam Ed25519)

-- | 256 bytes, which is a 2048-bit key: jose asks for the size in bytes.
generateRSAKeyPair :: IO (JWK, JWK)
generateRSAKeyPair = keyPairOf (RSAGenParam 256)

keyPairOf :: KeyMaterialGenParam -> IO (JWK, JWK)
keyPairOf param = do
  key <- set jwkKid (Just aKid) <$> genJWK param
  case view asPublicKey key of
    Nothing -> expectationFailure "A generated key pair has a public half."
    Just publicKey -> pure (key, publicKey)

generateKeyNamed :: Text -> IO JWK
generateKeyNamed name = set jwkKid (Just name) <$> genJWK (OKPGenParam Ed25519)

-- | A fetch that answers the same thing every time, and a count of how often
-- it was asked.
--
-- Counting is the whole point: what 'verificationKey' decides is when to ask
-- the issuer, so a test of it has to be able to see that. Fetching is a
-- parameter of that function rather than something hidden behind it, so this
-- is the real argument it takes and not a stand-in for one.
countedFetch :: Maybe [JWK] -> IO (IORef Int, IO (Maybe [JWK]))
countedFetch answer = do
  asked <- newIORef 0
  pure (asked, modifyIORef' asked (+ 1) >> pure answer)
