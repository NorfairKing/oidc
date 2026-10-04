-- | Deciding whether a bearer token is a credential, from end to end.
--
-- "OIDC.Token" answers that for one issuer whose key is already in hand. This
-- is the whole of it: which of the issuers a service federates with signed
-- the token, that issuer's key for it, and what the issuer said.
module OIDC.Federation
  ( Federation,
    verificationsByIssuer,
    newFederation,
    Outcome (..),
    authenticate,
  )
where

import Control.Monad (foldM)
import qualified Data.ByteString as SB
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Data.Time (UTCTime)
import OIDC.KeySet
import OIDC.Provider
import OIDC.Token
import UnliftIO

-- | The issuers a service federates with, and the keys each of them has
-- published so far.
--
-- Keyed by issuer because that is the only thing a token offers before
-- anything about it has been checked: a service that federates with nobody is
-- an empty one, which is almost every service.
newtype Federation = Federation (Map Issuer FederatedIssuer)

data FederatedIssuer = FederatedIssuer
  { federatedIssuerVerification :: !Verification,
    federatedIssuerKeySet :: !KeySet
  }

-- | The issuers these settings are about, by the name each calls itself.
--
-- 'Left' names an issuer configured twice, which is a configuration nobody
-- can mean: only one of the two could ever be reached, and which one is an
-- accident of the order they were written in. Separate from 'newFederation'
-- so that a service reading its settings can refuse them before it starts.
verificationsByIssuer :: [Verification] -> Either Issuer (Map Issuer Verification)
verificationsByIssuer = foldM addVerification Map.empty
  where
    addVerification ::
      Map Issuer Verification ->
      Verification ->
      Either Issuer (Map Issuer Verification)
    addVerification verifications verification =
      let issuer = verificationIssuer verification
       in if Map.member issuer verifications
            then Left issuer
            else Right (Map.insert issuer verification verifications)

newFederation :: (MonadIO m) => Map Issuer Verification -> m Federation
newFederation verifications =
  Federation
    <$> traverse
      ( \verification -> do
          keySet <- newKeySet
          pure
            FederatedIssuer
              { federatedIssuerVerification = verification,
                federatedIssuerKeySet = keySet
              }
      )
      verifications

-- | The issuer a token naming this one is to be checked against.
federatedIssuer :: Federation -> Issuer -> Maybe FederatedIssuer
federatedIssuer (Federation issuers) issuer = Map.lookup issuer issuers

-- | What a bearer token turned out to be.
data Outcome
  = -- | No issuer this service federates with is named by this token, which
    -- covers both somebody else's credential and something that is not a
    -- token at all. Nothing was checked and there is nothing to report: a
    -- service that answered differently here would be telling whoever asked
    -- which issuers it trusts.
    NotFederated
  | Refused !Refusal
  | Accepted !Claims
  deriving (Show, Eq)

-- | Check a bearer token against the issuers a service federates with.
--
-- The time is given rather than read, so that a caller can say which instant
-- a request is being judged at, and so that this is testable without a clock.
authenticate ::
  (MonadUnliftIO m) =>
  -- | How to fetch an issuer's key set. Only called for an issuer this
  -- service federates with, and only when a token names a key that is not
  -- held yet.
  (Issuer -> m (Maybe [JWK])) ->
  Federation ->
  UTCTime ->
  SB.ByteString ->
  m Outcome
authenticate fetch federation now token =
  case unverifiedIssuer token >>= federatedIssuer federation of
    Nothing -> pure NotFederated
    Just issuer -> case decodeToken token of
      Left refusal -> pure (Refused refusal)
      Right signedJWT -> case tokenKid signedJWT of
        Nothing -> pure (Refused RefusalNamesNoKey)
        Just kid -> do
          let verification = federatedIssuerVerification issuer
          mKey <-
            verificationKey
              (fetch (verificationIssuer verification))
              (federatedIssuerKeySet issuer)
              kid
          case mKey of
            Nothing -> pure (Refused (RefusalNamesUnknownKey kid))
            Just key -> case verifyToken verification key now signedJWT of
              Left refusal -> pure (Refused refusal)
              Right claims -> pure (Accepted claims)
