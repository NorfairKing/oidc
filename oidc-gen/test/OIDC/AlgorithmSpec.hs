{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module OIDC.AlgorithmSpec (spec) where

import Autodocodec (eitherDecodeJSONViaCodec, toJSONViaCodec)
import qualified Crypto.JOSE.JWA.JWS as JWS
import qualified Data.Aeson as JSON
import Data.Either (isLeft)
import qualified Data.Set as Set
import OIDC
import OIDC.Gen ()
import Test.Syd
import Test.Syd.Validity

spec :: Spec
spec = do
  genValidSpec @Algorithm

  describe "the Algorithm codec" $ do
    it "reads back what it wrote" $
      forAllValid $ \algorithm ->
        eitherDecodeJSONViaCodec (JSON.encode (toJSONViaCodec algorithm))
          `shouldBe` Right (algorithm :: Algorithm)

    it "writes the name the JOSE registry gives it" $
      forAllValid $ \algorithm ->
        toJSONViaCodec algorithm `shouldBe` JSON.String (renderAlgorithm algorithm)

    -- The whole point of the type: neither of these is a name a caller can
    -- end up holding, whatever an issuer advertises or a configuration says.
    it "does not read an unsigned or symmetric algorithm" $
      map
        (\name -> eitherDecodeJSONViaCodec (JSON.encode (JSON.String name)) :: Either String Algorithm)
        ["none", "HS256", "HS384", "HS512"]
        `shouldSatisfy` all isLeft

  describe "renderAlgorithm" $ do
    it "round-trips with parseAlgorithm" $
      forAllValid $ \algorithm ->
        parseAlgorithm (renderAlgorithm algorithm) `shouldBe` Just algorithm

    it "names every algorithm differently" $
      let names = map renderAlgorithm [minBound .. maxBound :: Algorithm]
       in Set.size (Set.fromList names) `shouldBe` length names

  describe "parseAlgorithm" $ do
    -- The whole point of the type: neither of these is a name a caller can
    -- end up holding, whatever an issuer advertises or a configuration says.
    it "does not read an unsigned token's algorithm" $
      parseAlgorithm "none" `shouldBe` Nothing

    it "does not read a symmetric algorithm" $
      map parseAlgorithm ["HS256", "HS384", "HS512"] `shouldBe` [Nothing, Nothing, Nothing]

    it "does not read a name nobody registered" $
      parseAlgorithm "RS257" `shouldBe` Nothing

    it "does not read a name in the wrong case" $
      parseAlgorithm "rs256" `shouldBe` Nothing

  describe "algorithmJoseAlg" $ do
    it "is a different jose algorithm for each" $
      let algs = map algorithmJoseAlg [minBound .. maxBound :: Algorithm]
       in Set.size (Set.fromList algs) `shouldBe` length algs

    it "is the jose algorithm of the same name" $
      map algorithmJoseAlg [minBound .. maxBound]
        `shouldBe` [ JWS.EdDSA,
                     JWS.ES256,
                     JWS.ES384,
                     JWS.ES512,
                     JWS.PS256,
                     JWS.PS384,
                     JWS.PS512,
                     JWS.RS256,
                     JWS.RS384,
                     JWS.RS512
                   ]
