{-# LANGUAGE OverloadedStrings #-}

module OIDC.KeySetSpec (spec) where

import Crypto.JOSE.JWK (KeyMaterialGenParam (..), OKPCrv (..), genJWK)
import Data.IORef
import Data.Time
import OIDC
import OIDC.TestUtils
import Test.Syd

spec :: Spec
spec = do
  describe "verificationKey" $ do
    it "fetches the key set when it holds nothing" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (asked, fetch) <- countedFetch (Just [key])
      mKey <- verificationKey fetch keySet "the-key"
      mKey `shouldBe` Just key
      readIORef asked `shouldReturn` 1

    it "answers from what it holds rather than asking again" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (asked, fetch) <- countedFetch (Just [key])
      _ <- verificationKey fetch keySet "the-key"
      mKey <- verificationKey fetch keySet "the-key"
      mKey `shouldBe` Just key
      readIORef asked `shouldReturn` 1

    it "answers with no key when the issuer publishes none under that name" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (_, fetch) <- countedFetch (Just [key])
      verificationKey fetch keySet "another-key" `shouldReturn` Nothing

    -- Without this, a token carrying a name nobody published would turn every
    -- request it arrives on into a request to the issuer.
    it "does not ask the issuer again within the refetch interval" $ do
      keySet <- newKeySet
      (asked, fetch) <- countedFetch (Just [])
      _ <- verificationKey fetch keySet "the-key"
      _ <- verificationKey fetch keySet "the-key"
      _ <- verificationKey fetch keySet "the-key"
      readIORef asked `shouldReturn` 1

    it "counts a failed fetch as having asked" $ do
      keySet <- newKeySet
      (asked, fetch) <- countedFetch Nothing
      _ <- verificationKey fetch keySet "the-key"
      _ <- verificationKey fetch keySet "the-key"
      readIORef asked `shouldReturn` 1

    -- An issuer that is briefly unreachable must not take authentication down
    -- with it, so the keys that were held stay held.
    it "keeps the keys it holds when a fetch fails" $ do
      key <- generateKeyNamed "the-key"
      keySet <- newKeySet
      (_, goodFetch) <- countedFetch (Just [key])
      _ <- verificationKey goodFetch keySet "the-key"
      (_, badFetch) <- countedFetch Nothing
      verificationKey badFetch keySet "the-key" `shouldReturn` Just key

    -- A key with no name cannot say which key a token was signed with, and
    -- guessing is what looking the key up is meant to avoid.
    it "never answers with a key the issuer did not name" $ do
      key <- genJWK (OKPGenParam Ed25519)
      keySet <- newKeySet
      (_, fetch) <- countedFetch (Just [key])
      verificationKey fetch keySet "the-key" `shouldReturn` Nothing

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
      _ <- verificationKey fetch keySet "the-key"
      state <- readKeySetState keySet
      keySetStateKeys state `shouldBe` [key]

  describe "keyWithKid" $ do
    it "finds the key published under that name" $ do
      wanted <- generateKeyNamed "the-key"
      other <- generateKeyNamed "another-key"
      keyWithKid "the-key" [other, wanted] `shouldBe` Just wanted

    it "finds nothing in an empty key set" $
      keyWithKid "the-key" [] `shouldBe` Nothing
