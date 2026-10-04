{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- | Deciding whether a token an issuer signed is a credential here.
--
-- This is the resource server's half of OpenID Connect: something presents a
-- token it got elsewhere, and the question is whether to believe it. Every
-- function here is pure, including the signature check, because jose's
-- 'verifyJWTAt' takes the time to check against rather than reading a clock
-- and a 'JWK' is a key rather than a key store to go looking in. The only
-- part that is not here is finding that key, which is "OIDC.KeySet".
module OIDC.Token
  ( Refusal (..),
    renderRefusal,
    Claims (..),
    claimsLifetime,
    decodeToken,
    tokenKid,
    unverifiedIssuer,
    verifyToken,
  )
where

import Control.Lens (review, view, (&), (.~), (^?), _Just)
import Crypto.JOSE.Header (kid, param)
import Crypto.JOSE.JWK (JWK)
import Crypto.JOSE.JWS (header, signatures)
import Crypto.JWT
  ( ClaimsSet,
    HasClaimsSet (..),
    JWTError,
    NumericDate (..),
    SignedJWT,
    StringOrURI,
    algorithms,
    allowedSkew,
    claimAud,
    claimExp,
    claimIat,
    claimIss,
    claimJti,
    claimSub,
    decodeCompact,
    defaultJWTValidationSettings,
    issuerPredicate,
    stringOrUri,
    verifyJWTAt,
  )
import qualified Crypto.JWT as JWT
import qualified Data.Aeson as JSON
import qualified Data.Aeson.Key as Key
import qualified Data.Aeson.KeyMap as KeyMap
import qualified Data.ByteArray.Encoding as BA
import qualified Data.ByteString as SB
import qualified Data.ByteString.Lazy as LB
import qualified Data.List.NonEmpty as NE
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import qualified Data.Set as Set
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TE
import Data.Time
import OIDC.Algorithm
import OIDC.Provider

-- | Why a token is not a credential.
--
-- A caller answers every one of these the same way, so these constructors
-- exist to be told to whoever configured the issuer: they are the only one
-- who can tell a mistyped audience from an expired token, and the thing
-- holding the token is told neither.
data Refusal
  = RefusalMalformed !String
  | -- | The token names no key, so there is no way to say which of the
    -- issuer's keys it claims to be signed with.
    RefusalNamesNoKey
  | -- | The token names a key the issuer does not publish. Raised by the
    -- caller, from what "OIDC.KeySet" answered.
    RefusalNamesUnknownKey !Text
  | RefusalDoesNotVerify !JWTError
  | -- | The token names no issuer, so nothing says who signed it.
    RefusalHasNoIssuer
  | -- | The token carries no @aud@ claim at all, so nobody said it was for
    -- this service.
    RefusalHasNoAudience
  | -- | No @exp@, no @iat@, or the two in the wrong order. A token with no
    -- lifetime is not a short-lived token.
    RefusalHasNoLifetime
  | RefusalLivesTooLong !NominalDiffTime !NominalDiffTime
  | RefusalHasNoSubject
  deriving (Show, Eq)

renderRefusal :: Refusal -> String
renderRefusal = \case
  RefusalMalformed err -> unwords ["the token is not a signed JWT:", err]
  RefusalNamesNoKey ->
    "the token's header names no key, so it cannot say which of the issuer's keys signed it"
  RefusalNamesUnknownKey k ->
    unwords ["the token names the key", concat [show @Text k, ","], "which the issuer does not publish"]
  RefusalDoesNotVerify err -> unwords ["the token does not verify:", show @JWTError err]
  RefusalHasNoIssuer -> "the token names no issuer, so nothing says who signed it"
  RefusalHasNoAudience -> "the token says no audience, so nobody said it was for this service"
  RefusalHasNoLifetime ->
    "the token does not say when it was issued and when it expires, so it is not short-lived"
  RefusalLivesTooLong lifetime maximumLifetime ->
    unwords
      [ "the token lives for",
        show @NominalDiffTime lifetime,
        "but this issuer's tokens may live for at most",
        show @NominalDiffTime maximumLifetime
      ]
  RefusalHasNoSubject -> "the token has no subject, so nothing can be said about who it is"

-- | What a token that was accepted says, with every claim already read out.
--
-- The whole payload is kept beside the registered claims because an issuer
-- puts what a caller wants to authorise on at the top level, which is where
-- jose's own payload type stops looking. Handing the claims back like this
-- rather than as jose's 'ClaimsSet' is also what keeps lenses out of every
-- caller.
data Claims = Claims
  { claimsIssuer :: !Issuer,
    claimsSubject :: !Text,
    claimsAudiences :: ![TokenAudience],
    -- | The @jti@ claim, when the issuer sets one.
    claimsId :: !(Maybe Text),
    claimsIssuedAt :: !UTCTime,
    claimsExpiry :: !UTCTime,
    -- | Every claim at the top level of the payload, the registered ones
    -- included. There is no list here of names that are out of bounds, so
    -- there is no list to get out of step with what issuers send.
    claimsAll :: !(Map Text JSON.Value)
  }
  deriving (Show, Eq)

-- | How long the token lives: the time between its @iat@ and its @exp@.
claimsLifetime :: Claims -> NominalDiffTime
claimsLifetime claims = diffUTCTime (claimsExpiry claims) (claimsIssuedAt claims)

-- | A token's claims as jose reads them, and as the issuer wrote them.
--
-- Keeping the whole object beside the registered claims is what jose calls a
-- subtype.
data RawClaims = RawClaims
  { rawClaimsRegistered :: !ClaimsSet,
    rawClaimsAll :: !(Map Text JSON.Value)
  }

instance HasClaimsSet RawClaims where
  claimsSet f claims =
    fmap
      (\registered -> claims {rawClaimsRegistered = registered})
      (f (rawClaimsRegistered claims))

instance JSON.FromJSON RawClaims where
  parseJSON value =
    flip (JSON.withObject "RawClaims") value $ \object ->
      RawClaims
        <$> JSON.parseJSON value
        <*> pure (Map.mapKeys Key.toText (KeyMap.toMap object))

-- | The issuer a token says it has, before anything has checked that the
-- token is what it says it is.
--
-- Only ever good for choosing which issuer's settings and keys to check the
-- token against. A token that names an issuer it was not signed by is checked
-- against that issuer's keys and fails there, so nothing read here is trusted
-- that is not checked afterwards.
--
-- Read without jose because jose offers no way to look at a payload it has
-- not verified, which is the right default and the wrong thing here.
unverifiedIssuer :: SB.ByteString -> Maybe Issuer
unverifiedIssuer token = do
  payloadSegment <- case Text.splitOn "." (TE.decodeUtf8Lenient token) of
    [_, payloadSegment, _] -> Just payloadSegment
    _ -> Nothing
  payloadBytes <- case BA.convertFromBase BA.Base64URLUnpadded (TE.encodeUtf8 payloadSegment) of
    Left (_ :: String) -> Nothing
    Right payloadBytes -> Just (payloadBytes :: SB.ByteString)
  claims <- JSON.decodeStrict @ClaimsSet payloadBytes
  Issuer . review stringOrUri <$> view claimIss claims

decodeToken :: SB.ByteString -> Either Refusal SignedJWT
decodeToken token =
  case decodeCompact (LB.fromStrict token) of
    Left (err :: JWTError) -> Left (RefusalMalformed (show @JWTError err))
    Right signedJWT -> Right signedJWT

-- | The key a token's header names.
tokenKid :: SignedJWT -> Maybe Text
tokenKid signedJWT = signedJWT ^? signatures . header . kid . _Just . param

-- | Check a token against the issuer it names.
--
-- The key is the one the token's @kid@ named rather than every key the issuer
-- publishes, so a token whose header names one key and whose signature was
-- made with another is refused instead of being accepted on the strength of
-- the second.
verifyToken ::
  Verification ->
  JWK ->
  UTCTime ->
  SignedJWT ->
  Either Refusal Claims
verifyToken verification key now signedJWT = do
  let expectedIssuer = unIssuer (verificationIssuer verification)
  let expectedAudiences =
        NE.toList (NE.map unTokenAudience (verificationAudiences verification))
  -- Compared as the issuer spells them, which is how an issuer documents
  -- itself and how 'unverifiedIssuer' already picks the settings to use.
  -- Comparing what jose parsed them into instead would be a second answer to
  -- the same question, and a configured value that is no url would parse to
  -- nothing and quietly match nothing.
  let isExpected :: [Text] -> StringOrURI -> Bool
      isExpected expected actual = review stringOrUri actual `elem` expected
  let validationSettings =
        defaultJWTValidationSettings (isExpected expectedAudiences)
          & issuerPredicate .~ isExpected [expectedIssuer]
          & allowedSkew .~ verificationClockSkew verification
          & algorithms
            .~ Set.fromList
              ( NE.toList $
                  NE.map algorithmJoseAlg (verificationAlgorithms verification)
              )
  rawClaims <- case verifyJWTAt validationSettings key now signedJWT of
    Left (err :: JWTError) -> Left (RefusalDoesNotVerify err)
    Right rawClaims -> Right rawClaims
  let registered = rawClaimsRegistered rawClaims
  -- jose asks each of its predicates only about a claim the token carries, so
  -- a token missing one passes a check that was never made. A token nobody
  -- said was for this service is not for this service, however genuinely its
  -- issuer signed it, and a token naming no issuer was verified against a key
  -- it never claimed was its own.
  issuer <- case view claimIss registered of
    Nothing -> Left RefusalHasNoIssuer
    Just issuer -> Right (Issuer (review stringOrUri issuer))
  audiences <- case view claimAud registered of
    Just (JWT.Audience audiences@(_ : _)) ->
      Right (map (TokenAudience . review stringOrUri) audiences)
    _ -> Left RefusalHasNoAudience
  (issuedAt, expiry) <- case (view claimIat registered, view claimExp registered) of
    (Just (NumericDate issuedAt), Just (NumericDate expiry))
      | diffUTCTime expiry issuedAt >= 0 -> Right (issuedAt, expiry)
    _ -> Left RefusalHasNoLifetime
  let lifetime = diffUTCTime expiry issuedAt
  case verificationMaxTokenLifetime verification of
    Just maximumLifetime
      | lifetime > maximumLifetime -> Left (RefusalLivesTooLong lifetime maximumLifetime)
    _ -> Right ()
  subject <- case view claimSub registered of
    Nothing -> Left RefusalHasNoSubject
    Just subject -> Right (review stringOrUri subject)
  pure
    Claims
      { claimsIssuer = issuer,
        claimsSubject = subject,
        claimsAudiences = audiences,
        claimsId = view claimJti registered,
        claimsIssuedAt = issuedAt,
        claimsExpiry = expiry,
        claimsAll = rawClaimsAll rawClaims
      }
