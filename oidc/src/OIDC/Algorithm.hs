{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

-- | The signing algorithms a token may be signed with.
module OIDC.Algorithm
  ( Algorithm (..),
    allAlgorithms,
    algorithmJoseAlg,
    renderAlgorithm,
    parseAlgorithm,
  )
where

import Autodocodec
import qualified Crypto.JOSE.JWA.JWS as JWS
import Data.List (find)
import Data.List.NonEmpty (NonEmpty (..))
import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import Data.Validity
import GHC.Generics (Generic)

-- | An algorithm a token this library will verify may be signed with.
--
-- There is no @none@ constructor and no @HS*@ constructor, so an unsigned or
-- symmetrically signed token is not something a caller can ask for. Both are
-- the same hazard: @none@ is a token anybody can mint, and a symmetric key is
-- the key that verifies as well as the key that signs, so an issuer that
-- published it in a key set would have published the power to mint tokens.
data Algorithm
  = EdDSA
  | ES256
  | ES384
  | ES512
  | PS256
  | PS384
  | PS512
  | RS256
  | RS384
  | RS512
  deriving (Show, Eq, Enum, Bounded, Generic)

instance Validity Algorithm

-- | Written as the JOSE registry names it, which is how an issuer writes it
-- too.
instance HasCodec Algorithm where
  codec =
    stringConstCodec (NE.map (\algorithm -> (algorithm, renderAlgorithm algorithm)) allAlgorithms)
      <?> "a JSON Web Signature algorithm"

-- | Every algorithm this library will check.
--
-- Derived from 'Bounded' and 'Enum' rather than listed, so that one added to
-- the type is one this knows about without that having to be remembered.
allAlgorithms :: NonEmpty Algorithm
allAlgorithms = minBound :| drop 1 [minBound .. maxBound]

-- | The jose algorithm this is.
algorithmJoseAlg :: Algorithm -> JWS.Alg
algorithmJoseAlg = \case
  EdDSA -> JWS.EdDSA
  ES256 -> JWS.ES256
  ES384 -> JWS.ES384
  ES512 -> JWS.ES512
  PS256 -> JWS.PS256
  PS384 -> JWS.PS384
  PS512 -> JWS.PS512
  RS256 -> JWS.RS256
  RS384 -> JWS.RS384
  RS512 -> JWS.RS512

-- | The name the JOSE registry gives this algorithm, which is what an issuer
-- puts in a token header and in its discovery document.
renderAlgorithm :: Algorithm -> Text
renderAlgorithm = \case
  EdDSA -> "EdDSA"
  ES256 -> "ES256"
  ES384 -> "ES384"
  ES512 -> "ES512"
  PS256 -> "PS256"
  PS384 -> "PS384"
  PS512 -> "PS512"
  RS256 -> "RS256"
  RS384 -> "RS384"
  RS512 -> "RS512"

-- | The algorithm with this name, if it is one this library will verify.
--
-- Nothing for @none@ and for the @HS*@ family as much as for a name nobody
-- registered: they are all names a caller cannot act on.
parseAlgorithm :: Text -> Maybe Algorithm
parseAlgorithm name = find ((== name) . renderAlgorithm) [minBound .. maxBound]
