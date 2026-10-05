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
    parseJWKSet,

    -- * Re-exported so that holding a key does not mean depending on jose
    JWK,
  )
where

import Crypto.JOSE.JWK (JWK, JWKSet (..))
import qualified Data.Aeson as JSON
import qualified Data.ByteString.Lazy as LB
import Data.Text (Text)
import Data.Time
import OIDC.KeySet.Internal
import UnliftIO

-- | An issuer whose keys have not been asked for yet.
newKeySet :: (MonadIO m) => m KeySet
newKeySet =
  KeySet
    <$> newTVarIO
      KeySetState
        { keySetStateKeys = [],
          keySetStateAttempted = Nothing
        }
    <*> newMVar ()

-- | The key this issuer published for a token, fetching if it is not held
-- yet.
--
-- The fetch is only made when the key is not held and the issuer has not been
-- asked too recently, and it is made while holding the lock, so a hundred
-- requests arriving together make one request to the issuer. A fetch that
-- answers 'Nothing' leaves the keys that were held in place: an issuer that
-- is briefly unreachable must not take authentication down with it.
--
-- A request whose key is already held never takes that lock, so it is not
-- made to wait for a fetch it needs nothing from.
verificationKey ::
  (MonadUnliftIO m) =>
  -- | How to fetch this issuer's key set. Nothing if it could not be fetched,
  -- for whatever reason and however that was reported.
  m (Maybe [JWK]) ->
  KeySet ->
  -- | The @kid@ the token named, if it named one. See 'keyFor' for what an
  -- unnamed key is answered with.
  Maybe Text ->
  m (Maybe JWK)
verificationKey fetch keySet mKid = do
  -- Looked at before the lock is taken, because the lock is held across the
  -- fetch: a token naming a key that is already held must not wait behind an
  -- issuer that is slow to answer a question about some other key.
  held <- readKeySetState keySet
  case keyFor mKid (keySetStateKeys held) of
    Just key -> pure (Just key)
    Nothing -> withMVar (keySetFetchLock keySet) $ \() -> do
      -- Asked again under the lock, because the key may have arrived between
      -- the read above and here, in which case this is a request that waited
      -- for a fetch rather than one that needs another.
      state <- readKeySetState keySet
      case keyFor mKid (keySetStateKeys state) of
        Just key -> pure (Just key)
        Nothing -> do
          now <- liftIO getCurrentTime
          if not (refetchAllowed now state)
            then pure Nothing
            else do
              mKeys <- fetch
              case mKeys of
                -- The keys that were held stay held: an issuer that is
                -- briefly unreachable must not take authentication down with
                -- it. Only the attempt is recorded.
                Nothing -> do
                  atomically $
                    modifyTVar' (keySetState keySet) $ \current ->
                      current {keySetStateAttempted = Just now}
                  pure Nothing
                Just keys -> do
                  atomically $
                    writeTVar (keySetState keySet) $
                      KeySetState
                        { keySetStateKeys = keys,
                          keySetStateAttempted = Just now
                        }
                  pure (keyFor mKid keys)

-- | Read the key set an issuer publishes.
--
-- Here so that fetching one does not mean depending on jose to read the
-- answer. The fetch itself is still the caller's.
parseJWKSet :: LB.ByteString -> Either String [JWK]
parseJWKSet body = case JSON.eitherDecode body of
  Left err -> Left err
  Right (JWKSet keys) -> Right keys
