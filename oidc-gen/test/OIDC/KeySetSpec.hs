{-# LANGUAGE NumericUnderscores #-}
{-# LANGUAGE OverloadedStrings #-}

module OIDC.KeySetSpec (spec) where

import Crypto.JOSE.JWK (JWKSet (..), KeyMaterialGenParam (..), OKPCrv (..), genJWK)
import qualified Data.Aeson as JSON
import Data.Time
import OIDC
import OIDC.KeySet.Internal
import OIDC.TestUtils
import Test.Syd
import UnliftIO

spec :: Spec
spec = do
  describe "verificationKey" $ do
    it "fetches the key set when it holds nothing" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (asked, fetch) <- countedFetch (Just [key])
      mKey <- verificationKey fetch keySet (Just "the-key")
      mKey `shouldBe` Just key
      readIORef asked `shouldReturn` 1

    it "answers from what it holds rather than asking again" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (asked, fetch) <- countedFetch (Just [key])
      _ <- verificationKey fetch keySet (Just "the-key")
      mKey <- verificationKey fetch keySet (Just "the-key")
      mKey `shouldBe` Just key
      readIORef asked `shouldReturn` 1

    it "answers with no key when the issuer publishes none under that name" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (_, fetch) <- countedFetch (Just [key])
      verificationKey fetch keySet (Just "another-key") `shouldReturn` Nothing

    -- Without this, a token carrying a name nobody published would turn every
    -- request it arrives on into a request to the issuer.
    it "does not ask the issuer again within the refetch interval" $ do
      keySet <- newKeySet
      (asked, fetch) <- countedFetch (Just [])
      _ <- verificationKey fetch keySet (Just "the-key")
      _ <- verificationKey fetch keySet (Just "the-key")
      _ <- verificationKey fetch keySet (Just "the-key")
      readIORef asked `shouldReturn` 1

    it "counts a failed fetch as having asked" $ do
      keySet <- newKeySet
      (asked, fetch) <- countedFetch Nothing
      _ <- verificationKey fetch keySet (Just "the-key")
      _ <- verificationKey fetch keySet (Just "the-key")
      readIORef asked `shouldReturn` 1

    -- An issuer that is briefly unreachable must not take authentication down
    -- with it, so the keys that were held stay held.
    it "keeps the keys it holds when a fetch fails" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (_, goodFetch) <- countedFetch (Just [key])
      _ <- verificationKey goodFetch keySet (Just "the-key")
      (_, badFetch) <- countedFetch Nothing
      verificationKey badFetch keySet (Just "the-key") `shouldReturn` Just key

    -- A key with no name cannot say which key a token was signed with, and
    -- guessing is what looking the key up is meant to avoid.
    it "never answers with a key the issuer did not name" $ do
      key <- genJWK (OKPGenParam Ed25519)
      keySet <- newKeySet
      (_, fetch) <- countedFetch (Just [key])
      verificationKey fetch keySet (Just "the-key") `shouldReturn` Nothing

    it "answers a token that names no key with the only key there is" $ do
      key <- genJWK (OKPGenParam Ed25519)
      keySet <- newKeySet
      (_, fetch) <- countedFetch (Just [key])
      verificationKey fetch keySet Nothing `shouldReturn` Just key

    it "answers a token that names no key with nothing when the issuer publishes two" $ do
      one <- generateKeyNamed "one"
      two <- generateKeyNamed "two"
      keySet <- newKeySet
      (_, fetch) <- countedFetch (Just [one, two])
      verificationKey fetch keySet Nothing `shouldReturn` Nothing

    -- The lock a fetch is made under is held across that fetch, so a request
    -- whose key is already held has to be answered without taking it. A
    -- hundred requests queued behind one slow issuer, for keys that issuer
    -- has already published, is the failure this prevents.
    --
    -- Two keys rather than one, because with a single key held a lookup that
    -- ignored the name it was given would still find it, and this has to fail
    -- if the name stops being used.
    it "answers from what it holds while a fetch for another key is in flight" $ do
      one <- generateKeyNamed "one"
      two <- generateKeyNamed "two"
      -- Built rather than fetched into, so that the keys are held and the
      -- issuer has still never been asked, which is what lets the fetch below
      -- actually run.
      keySet <-
        KeySet
          <$> newTVarIO
            KeySetState
              { keySetStateKeys = [one, two],
                keySetStateAttempted = Nothing
              }
          <*> newMVar ()
      started <- newEmptyMVar
      released <- newEmptyMVar
      let blockingFetch = do
            putMVar started ()
            takeMVar released
            pure (Just [one, two])
      inFlight <- async $ verificationKey blockingFetch keySet (Just "unpublished")
      -- Waited for rather than assumed: until the fetch is running the lock
      -- is free, and a request that took it would prove nothing.
      takeMVar started
      held <- timeout 1_000_000 $ verificationKey blockingFetch keySet (Just "two")
      putMVar released ()
      _ <- wait inFlight
      held `shouldBe` Just (Just two)

    -- The request that waited for a fetch must be answered by it. Without the
    -- second look under the lock it would find the keys unchanged from before
    -- it waited, and then be told the issuer had been asked too recently to
    -- ask again.
    -- Two keys, and each request asking for a different one, so that a second
    -- look which ignored the name it was given could not stand in for one
    -- that honoured it.
    it "answers a request that waited for a fetch with what that fetch brought" $ do
      one <- generateKeyNamed "one"
      two <- generateKeyNamed "two"
      keySet <- newKeySet
      asked <- newIORef (0 :: Int)
      started <- newEmptyMVar
      released <- newEmptyMVar
      let blockingFetch = do
            modifyIORef' asked (+ 1)
            putMVar started ()
            takeMVar released
            pure (Just [one, two])
      first <- async $ verificationKey blockingFetch keySet (Just "one")
      takeMVar started
      second <- async $ verificationKey blockingFetch keySet (Just "two")
      -- Asserted rather than assumed: this both says the second request is
      -- waiting on the lock and gives it the time to get there.
      timeout 100_000 (wait second) `shouldReturn` Nothing
      putMVar released ()
      wait first `shouldReturn` Just one
      wait second `shouldReturn` Just two
      readIORef asked `shouldReturn` 1

  describe "refetchAllowed" $ do
    it "allows a fetch when the issuer has never been asked" $
      refetchAllowed
        aNow
        KeySetState
          { keySetStateKeys = [],
            keySetStateAttempted = Nothing
          }
        `shouldBe` True

    it "refuses a fetch a moment after the last one" $
      refetchAllowed
        aNow
        KeySetState
          { keySetStateKeys = [],
            keySetStateAttempted = Just (addUTCTime (-1) aNow)
          }
        `shouldBe` False

    it "refuses a fetch just before the interval is up" $
      refetchAllowed
        aNow
        KeySetState
          { keySetStateKeys = [],
            keySetStateAttempted = Just (addUTCTime (-minimumRefetchInterval + 0.001) aNow)
          }
        `shouldBe` False

    it "allows a fetch exactly when the interval is up" $
      refetchAllowed
        aNow
        KeySetState
          { keySetStateKeys = [],
            keySetStateAttempted = Just (addUTCTime (-minimumRefetchInterval) aNow)
          }
        `shouldBe` True

  describe "readKeySetState" $ do
    it "holds nothing and has asked nobody to begin with" $ do
      keySet <- newKeySet
      state <- readKeySetState keySet
      state
        `shouldBe` KeySetState
          { keySetStateKeys = [],
            keySetStateAttempted = Nothing
          }

    it "holds what was fetched" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (_, fetch) <- countedFetch (Just [key])
      _ <- verificationKey fetch keySet (Just "the-key")
      state <- readKeySetState keySet
      keySetStateKeys state `shouldBe` [key]

  describe "parseJWKSet" $ do
    it "reads back a key set as an issuer publishes it" $ do
      key <- generateKeyNamed "the-key"
      parseJWKSet (JSON.encode (JWKSet [key])) `shouldBe` Right [key]

    -- An issuer that has rotated publishes the old key beside the new one,
    -- so reading only the first would stop every token in flight.
    it "reads back every key in the set" $ do
      old <- generateKeyNamed "the-old-key"
      new <- generateKeyNamed "the-new-key"
      parseJWKSet (JSON.encode (JWKSet [old, new])) `shouldBe` Right [old, new]

    it "reads an issuer that publishes no keys at all" $
      parseJWKSet (JSON.encode (JWKSet [])) `shouldBe` Right []

    it "says what is wrong with something that is not a key set" $
      parseJWKSet (JSON.encode (JSON.object [("keys", JSON.String "not a list")]))
        `shouldBe` Left "Error in $.keys: parsing [] failed, expected Array, but encountered String"

    it "says what is wrong with something that is not JSON" $
      parseJWKSet "not json at all"
        `shouldBe` Left "Unexpected \"not json at all\", expecting JSON value"

  describe "keyFor" $ do
    it "finds the key a token named" $ do
      wanted <- generateKeyNamed "the-key"
      other <- generateKeyNamed "another-key"
      keyFor (Just "the-key") [other, wanted] `shouldBe` Just wanted

    it "finds the only key there is for a token that named none" $ do
      key <- genJWK (OKPGenParam Ed25519)
      keyFor Nothing [key] `shouldBe` Just key

    it "finds nothing for a token that named none when there are two keys" $ do
      one <- generateKeyNamed "one"
      two <- generateKeyNamed "two"
      keyFor Nothing [one, two] `shouldBe` Nothing

    it "finds nothing for a token that named none when there are no keys" $
      keyFor Nothing [] `shouldBe` Nothing

  describe "keyWithKid" $ do
    it "finds the key published under that name" $ do
      wanted <- generateKeyNamed "the-key"
      other <- generateKeyNamed "another-key"
      keyWithKid "the-key" [other, wanted] `shouldBe` Just wanted

    it "finds nothing in an empty key set" $
      keyWithKid "the-key" [] `shouldBe` Nothing
