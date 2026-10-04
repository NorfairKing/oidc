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
    <$> newMVar
      KeySetState
        { keySetStateKeys = [],
          keySetStateAttempted = Nothing
        }

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

-- | Read the key set an issuer publishes.
--
-- Here so that fetching one does not mean depending on jose to read the
-- answer. The fetch itself is still the caller's.
parseJWKSet :: LB.ByteString -> Either String [JWK]
parseJWKSet body = case JSON.eitherDecode body of
  Left err -> Left err
  Right (JWKSet keys) -> Right keys
