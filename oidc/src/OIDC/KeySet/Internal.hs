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
-- An 'MVar' rather than a 'TVar' because it is also the lock a fetch is made
-- under: requests that arrive while one is in flight wait for its answer
-- instead of each starting a fetch of their own.
newtype KeySet = KeySet {unKeySet :: MVar KeySetState}

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
readKeySetState :: (MonadIO m) => KeySet -> m KeySetState
readKeySetState = readMVar . unKeySet

refetchAllowed :: UTCTime -> KeySetState -> Bool
refetchAllowed now state = case keySetStateAttempted state of
  Nothing -> True
  Just attempted -> diffUTCTime now attempted >= minimumRefetchInterval

-- | The one key published under this @kid@.
--
-- A key with no @kid@ at all is never this key: a key set that names none of
-- its keys cannot say which one a token was signed with, and guessing is what
-- looking the key up is meant to avoid.
keyWithKid :: Text -> [JWK] -> Maybe JWK
keyWithKid kid = find ((== Just kid) . view jwkKid)
