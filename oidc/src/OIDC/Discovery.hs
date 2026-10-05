{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingVia #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Asking an issuer where its keys are, instead of being told.
--
-- The document itself is fetched by the caller, as in "OIDC.KeySet": what is
-- here is the url to fetch and what the answer has to say to be believed.
module OIDC.Discovery
  ( discoveryURL,
    Discovery (..),
    parseDiscovery,
  )
where

import Autodocodec
import Data.Aeson (FromJSON, ToJSON)
import qualified Data.Aeson as JSON
import qualified Data.ByteString.Lazy as LB
import Data.Maybe (mapMaybe)
import Data.Text (Text)
import qualified Data.Text as Text
import Data.Validity
import Data.Validity.Text ()
import GHC.Generics (Generic)
import OIDC.Algorithm
import OIDC.Provider

-- | Where an issuer publishes what it can do.
--
-- The path is fixed by OpenID Connect Discovery and is appended to the issuer
-- exactly as the issuer spells itself, trailing slash and all, because the
-- issuer is an identifier here and not a url to be tidied up.
discoveryURL :: Issuer -> Text
discoveryURL (Issuer issuer) =
  Text.concat [Text.dropWhileEnd (== '/') issuer, "/.well-known/openid-configuration"]

-- | The parts of an issuer's discovery document that say how to check its
-- tokens.
--
-- Not the whole document: the rest of it is about getting a token, which is
-- the client's half of OpenID Connect and not this library's.
data Discovery = Discovery
  { discoveryIssuer :: !Issuer,
    discoveryJWKSURL :: !Text,
    -- | The algorithms the issuer says it signs id tokens with, with any name
    -- this library will not check left out.
    --
    -- Advertised rather than promised: an issuer may sign with less than it
    -- lists, and listing one is not a reason to accept it. Good for telling
    -- somebody their allowlist and their issuer have nothing in common.
    discoveryAlgorithms :: ![Algorithm]
  }
  deriving (Show, Eq, Generic)
  deriving (FromJSON, ToJSON) via (Autodocodec Discovery)

instance Validity Discovery

instance HasCodec Discovery where
  codec =
    object "Discovery" $
      Discovery
        <$> requiredField "issuer" "the issuer this document belongs to"
          .= discoveryIssuer
        <*> requiredField "jwks_uri" "where this issuer publishes its keys"
          .= discoveryJWKSURL
        <*> optionalFieldWithOmittedDefaultWith
          "id_token_signing_alg_values_supported"
          advertisedAlgorithmsCodec
          []
          "the algorithms this issuer says it signs id tokens with"
          .= discoveryAlgorithms

-- | The advertised algorithms, keeping only the ones this library would
-- check.
--
-- Read as text and filtered rather than read as 'Algorithm's, because every
-- issuer advertises names this library has no constructor for: Keycloak lists
-- the whole @HS*@ family. A document naming one of those is a document to
-- read, not a document to refuse.
advertisedAlgorithmsCodec :: JSONCodec [Algorithm]
advertisedAlgorithmsCodec =
  dimapCodec (mapMaybe parseAlgorithm) (map renderAlgorithm) codec

-- | Read a discovery document, which must be the one belonging to the issuer
-- it was fetched for.
--
-- The issuer is checked rather than taken from the document, because a
-- document is only evidence about the issuer that served it. Taking its word
-- would let whatever answered that url nominate the keys to trust.
parseDiscovery :: Issuer -> LB.ByteString -> Either String Discovery
parseDiscovery expectedIssuer body = do
  discovery <- JSON.eitherDecode body
  if discoveryIssuer discovery /= expectedIssuer
    then
      Left $
        unwords
          [ "the document at the discovery url of",
            show (unIssuer expectedIssuer),
            "says it belongs to",
            concat [show (unIssuer (discoveryIssuer discovery)), ","],
            "so it is not that issuer's"
          ]
    else Right discovery
