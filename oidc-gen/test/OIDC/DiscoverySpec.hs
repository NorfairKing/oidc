{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module OIDC.DiscoverySpec (spec) where

import qualified Data.Aeson as JSON
import qualified Data.Aeson.KeyMap as KeyMap
import OIDC
import OIDC.Gen ()
import Test.Syd
import Test.Syd.Validity
import Test.Syd.Validity.Aeson

spec :: Spec
spec = do
  genValidSpec @Discovery
  jsonSpec @Discovery

  describe "discoveryURL" $ do
    it "is the well-known path under the issuer" $
      discoveryURL (Issuer "https://sts.example.com")
        `shouldBe` "https://sts.example.com/.well-known/openid-configuration"

    it "is the well-known path under an issuer that has a path of its own" $
      discoveryURL (Issuer "https://sts.example.com/dex")
        `shouldBe` "https://sts.example.com/dex/.well-known/openid-configuration"

    -- An issuer that spells itself with a trailing slash and one that does
    -- not are the same issuer as far as where its document is, and a doubled
    -- slash is a different path to most servers.
    it "is the well-known path under an issuer written with a trailing slash" $
      discoveryURL (Issuer "https://sts.example.com/")
        `shouldBe` "https://sts.example.com/.well-known/openid-configuration"

  describe "parseDiscovery" $ do
    -- A document as an issuer serves it, cut down to the fields this library
    -- reads and enough of the ones beside them that it has to step over some.
    let aDocument =
          JSON.object
            [ ("issuer", "https://sts.example.com"),
              ("jwks_uri", "https://sts.example.com/keys"),
              ("authorization_endpoint", "https://sts.example.com/auth"),
              ("token_endpoint", "https://sts.example.com/token"),
              ("response_types_supported", JSON.toJSON @[String] ["code"]),
              ("subject_types_supported", JSON.toJSON @[String] ["public"]),
              ("id_token_signing_alg_values_supported", JSON.toJSON @[String] ["EdDSA", "RS256"])
            ]

    it "reads the key set url an issuer publishes" $
      parseDiscovery (Issuer "https://sts.example.com") (JSON.encode aDocument)
        `shouldBe` Right
          Discovery
            { discoveryIssuer = Issuer "https://sts.example.com",
              discoveryJWKSURL = "https://sts.example.com/keys",
              discoveryAlgorithms = [EdDSA, RS256]
            }

    -- A document is only evidence about the issuer that served it. Taking its
    -- word for whose it is would let whatever answered that url nominate the
    -- keys to trust.
    it "refuses a document that says it belongs to another issuer" $
      parseDiscovery (Issuer "https://elsewhere.example.com") (JSON.encode aDocument)
        `shouldBe` Left
          "the document at the discovery url of \"https://elsewhere.example.com\" says it belongs to \"https://sts.example.com\", so it is not that issuer's"

    it "leaves out an advertised algorithm it will not verify" $
      fmap
        discoveryAlgorithms
        ( parseDiscovery (Issuer "https://sts.example.com") $
            JSON.encode $ case aDocument of
              JSON.Object object ->
                JSON.Object $
                  KeyMap.insert
                    "id_token_signing_alg_values_supported"
                    (JSON.toJSON @[String] ["none", "HS256", "RS256"])
                    object
              other -> other
        )
        `shouldBe` Right [RS256]

    it "refuses a document whose advertised algorithms are not names" $
      parseDiscovery
        (Issuer "https://sts.example.com")
        ( JSON.encode $ case aDocument of
            JSON.Object object ->
              JSON.Object
                ( KeyMap.insert
                    "id_token_signing_alg_values_supported"
                    (JSON.toJSON @[Int] [1, 2])
                    object
                )
            other -> other
        )
        `shouldSatisfy` \case
          Left _ -> True
          Right _ -> False

    it "reads a document that advertises no algorithms at all" $
      fmap
        discoveryAlgorithms
        ( parseDiscovery (Issuer "https://sts.example.com") $
            JSON.encode $
              JSON.object
                [ ("issuer", "https://sts.example.com"),
                  ("jwks_uri", "https://sts.example.com/keys")
                ]
        )
        `shouldBe` Right []

    it "says what is wrong with a document that is not JSON" $
      parseDiscovery (Issuer "https://sts.example.com") "not json at all"
        `shouldBe` Left "Unexpected \"not json at all\", expecting JSON value"

    it "says what is wrong with a document that names no key set" $
      parseDiscovery
        (Issuer "https://sts.example.com")
        (JSON.encode (JSON.object [("issuer", "https://sts.example.com")]))
        `shouldBe` Left "Error in $: key \"jwks_uri\" not found"

    it "says what is wrong with a document that names no issuer" $
      parseDiscovery
        (Issuer "https://sts.example.com")
        (JSON.encode (JSON.object [("jwks_uri", "https://sts.example.com/keys")]))
        `shouldBe` Left "Error in $: key \"issuer\" not found"
