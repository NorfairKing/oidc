{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Who a token has to be from, and what has to be true of it, for this
-- library to accept it.
module OIDC.Provider
  ( Issuer (..),
    TokenAudience (..),
    Verification (..),
    verificationFor,
  )
where

import Autodocodec
import Data.List.NonEmpty (NonEmpty (..))
import Data.Text (Text)
import Data.Time (NominalDiffTime)
import Data.Validity
import Data.Validity.Text ()
import Data.Validity.Time ()
import GHC.Generics (Generic)
import OIDC.Algorithm

-- | An issuer, exactly as it spells itself in the @iss@ claim.
--
-- Compared as text rather than as a parsed url, because that is how an issuer
-- documents itself and how a token carries it. Two urls that a parser would
-- call equal are still two different issuers as far as this library is
-- concerned, which is the safe direction to be wrong in.
newtype Issuer = Issuer {unIssuer :: Text}
  deriving (Show, Eq, Ord, Generic)

instance Validity Issuer

instance HasCodec Issuer where
  codec = dimapCodec Issuer unIssuer codec <?> "an issuer, exactly as it spells itself"

-- | An audience, exactly as the issuer spells it in the @aud@ claim.
--
-- This is the name the issuer knows the service by, and saying it is what
-- stops a token minted for one service being replayed against another.
newtype TokenAudience = TokenAudience {unTokenAudience :: Text}
  deriving (Show, Eq, Generic)

instance Validity TokenAudience

instance HasCodec TokenAudience where
  codec =
    dimapCodec TokenAudience unTokenAudience codec
      <?> "a name the issuer knows this service by"

-- | Everything about an issuer that a token is checked against.
--
-- There is no key here: 'OIDC.Token.verifyToken' takes the one key the token
-- names, so that a token whose header names one key and whose signature was
-- made with another is refused rather than accepted on the strength of the
-- second. Which key that is is 'OIDC.KeySet'.
data Verification = Verification
  { verificationIssuer :: !Issuer,
    -- | A token naming any one of these is for us.
    verificationAudiences :: !(NonEmpty TokenAudience),
    -- | The algorithms this issuer is allowed to have signed with.
    --
    -- An allowlist rather than whatever the token's header asks for, so that
    -- an issuer holding both an RSA and an EC key cannot be made to verify
    -- against the weaker one by a token that says so.
    verificationAlgorithms :: !(NonEmpty Algorithm),
    -- | The longest a token from this issuer may live, measured from @iat@ to
    -- @exp@.
    --
    -- Nothing accepts whatever lifetime the issuer chose. A bound here is the
    -- only thing that makes "short-lived" mean anything: an issuer that mints
    -- a year-long token has minted a credential, and the point of federation
    -- is that there is no credential to lose.
    verificationMaxTokenLifetime :: !(Maybe NominalDiffTime),
    -- | How far out of step with the issuer's clock this one may be, applied
    -- to @exp@, @nbf@ and @iat@.
    verificationClockSkew :: !NominalDiffTime
  }
  deriving (Show, Eq, Generic)

instance Validity Verification where
  validate verification =
    genericValidate verification
      <> declare
        "the clock skew is not negative"
        (verificationClockSkew verification >= 0)
      <> declare
        "the maximum token lifetime, where there is one, is positive"
        (all (> 0) (verificationMaxTokenLifetime verification))

-- | The settings that say to accept this issuer's tokens for this audience,
-- and nothing else about them.
--
-- A starting point to adjust rather than the whole of the type, so that a
-- field added later is one every caller is asked about by the compiler only
-- where it builds the record itself.
verificationFor :: Issuer -> TokenAudience -> NonEmpty Algorithm -> Verification
verificationFor issuer audience algorithms =
  Verification
    { verificationIssuer = issuer,
      verificationAudiences = audience :| [],
      verificationAlgorithms = algorithms,
      verificationMaxTokenLifetime = Nothing,
      verificationClockSkew = 0
    }
