{-# LANGUAGE LambdaCase #-}

-- | What 'OIDC.KeySet' is made of.
--
-- Here rather than beside it so that the module a caller imports offers only
-- what a caller needs. These are the pieces the decision is assembled from,
-- exported so that each can be tested for itself rather than through a fetch.
module OIDC.KeySet.Internal
  ( KeySet (..),
    KeySetState (..),
    readKeySetState,
    refetchAllowed,
    minimumRefetchInterval,
    keyFor,
    keyWithKid,
  )
where

import Control.Lens (view)
import Crypto.JOSE.JWK (JWK, jwkKid)
import Data.List (find)
import Data.Text (Text)
import Data.Time
import UnliftIO

-- | The keys one issuer published, and when it was last asked for them.
--
-- The state and the lock are two things rather than one. A single 'MVar'
-- would serve as both, but taking it to make a fetch empties it, so every
-- read would block for as long as that fetch takes: a request whose key was
-- published long ago would wait on an issuer it needs nothing from. The lock
-- is held across the fetch on purpose, so it must be a lock nobody reads
-- through.
data KeySet = KeySet
  { keySetState :: !(TVar KeySetState),
    -- | Held while fetching, so that requests arriving together make one
    -- request to the issuer rather than one each.
    keySetFetchLock :: !(MVar ())
  }

data KeySetState = KeySetState
  { keySetStateKeys :: ![JWK],
    -- | When a fetch was last attempted, whether or not it worked.
    --
    -- A failed attempt counts, so that an issuer that is down is asked at the
    -- same rate as one that is up rather than once per request.
    keySetStateAttempted :: !(Maybe UTCTime)
  }
  deriving (Show, Eq)

-- | How long after asking an issuer for its keys this will ask again.
--
-- This is what stops a token carrying a @kid@ nobody ever published from
-- turning each request into a request to the issuer. It is also the longest a
-- rotation can go unnoticed, which is why it is a minute rather than an hour:
-- a key set is a few hundred bytes and an issuer publishes it on a CDN.
minimumRefetchInterval :: NominalDiffTime
minimumRefetchInterval = 60

-- | What is held right now, for a caller that wants to look without asking
-- for anything.
--
-- Never waits, including while a fetch is in flight.
readKeySetState :: (MonadIO m) => KeySet -> m KeySetState
readKeySetState = readTVarIO . keySetState

refetchAllowed :: UTCTime -> KeySetState -> Bool
refetchAllowed now state = case keySetStateAttempted state of
  Nothing -> True
  Just attempted -> diffUTCTime now attempted >= minimumRefetchInterval

-- | The key a token asks for: the one it named, or the only one there is when
-- it named none.
--
-- A header carrying no @kid@ is a header RFC 7515 allows, and an issuer that
-- publishes exactly one key has already said which key signed it. Refusing
-- those outright would mean refusing every token from such an issuer, with
-- nothing but a log line to say why.
--
-- With none published, or more than one, there is nothing to go on. Trying
-- each key in turn would verify the token against a key the issuer never said
-- it used, which is the guessing that naming a key exists to avoid.
keyFor :: Maybe Text -> [JWK] -> Maybe JWK
keyFor = \case
  Just kid -> keyWithKid kid
  Nothing -> \case
    [key] -> Just key
    _ -> Nothing

-- | The one key published under this @kid@.
--
-- A key with no @kid@ at all is never this key: a key set that names none of
-- its keys cannot say which one a token was signed with, and guessing is what
-- looking the key up is meant to avoid.
keyWithKid :: Text -> [JWK] -> Maybe JWK
keyWithKid kid = find ((== Just kid) . view jwkKid)
