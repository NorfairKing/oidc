{-# LANGUAGE ScopedTypeVariables #-}

-- | The keys an issuer signs its tokens with, held between requests.
--
-- Fetched when a token names a key that is not held yet, rather than kept
-- fresh in the background. A service nobody presents a token to then asks the
-- issuer nothing at all, and an issuer that rotates its keys is followed on
-- the first token signed with the new one instead of at the next tick of
-- something.
--
-- Fetching is the caller's, which is what keeps an HTTP client, a retry
-- policy and a logger out of this library. What is here is the part that is
-- easy to get wrong: one fetch at a time, a floor under how often an issuer
-- is asked, and looking a key up by the name the token gave it.
module OIDC.KeySet
  ( KeySet,
    newKeySet,
    verificationKey,
    KeySetState (..),
    readKeySetState,
    refetchAllowed,
    minimumRefetchInterval,
    keyWithKid,
    parseJWKSet,

    -- * Re-exported so that holding a key does not mean depending on jose
    JWK,
  )
where

import Control.Lens (view)
import Crypto.JOSE.JWK (JWK, JWKSet (..), jwkKid)
import qualified Data.Aeson as JSON
import qualified Data.ByteString.Lazy as LB
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

-- | An issuer whose keys have not been asked for yet.
newKeySet :: (MonadIO m) => m KeySet
newKeySet =
  KeySet
    <$> newMVar
      KeySetState
        { keySetStateKeys = [],
          keySetStateAttempted = Nothing
        }

-- | What is held right now, for a caller that wants to look without asking
-- for anything.
readKeySetState :: (MonadIO m) => KeySet -> m KeySetState
readKeySetState = readMVar . unKeySet

-- | The key this issuer published under this @kid@, fetching if it is not
-- held yet.
--
-- The fetch is only made when the key is not held and the issuer has not been
-- asked too recently, and it is made while holding the lock, so a hundred
-- requests arriving together make one request to the issuer. A fetch that
-- answers 'Nothing' leaves the keys that were held in place: an issuer that
-- is briefly unreachable must not take authentication down with it.
verificationKey ::
  (MonadUnliftIO m) =>
  -- | How to fetch this issuer's key set. Nothing if it could not be fetched,
  -- for whatever reason and however that was reported.
  m (Maybe [JWK]) ->
  KeySet ->
  -- | The @kid@ the token named.
  Text ->
  m (Maybe JWK)
verificationKey fetch (KeySet keySetVar) kid = do
  now <- liftIO getCurrentTime
  modifyMVar keySetVar $ \state ->
    case keyWithKid kid (keySetStateKeys state) of
      Just key -> pure (state, Just key)
      Nothing
        | not (refetchAllowed now state) -> pure (state, Nothing)
        | otherwise -> do
            mKeys <- fetch
            case mKeys of
              Nothing -> pure (state {keySetStateAttempted = Just now}, Nothing)
              Just keys ->
                pure
                  ( KeySetState
                      { keySetStateKeys = keys,
                        keySetStateAttempted = Just now
                      },
                    keyWithKid kid keys
                  )

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

-- | Read the key set an issuer publishes.
--
-- Here so that fetching one does not mean depending on jose to read the
-- answer. The fetch itself is still the caller's.
parseJWKSet :: LB.ByteString -> Either String [JWK]
parseJWKSet body = case JSON.eitherDecode body of
  Left err -> Left err
  Right (JWKSet keys) -> Right keys
