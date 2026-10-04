{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

-- | Checking the library against an issuer that really exists.
--
-- Every other test in this repository signs its own tokens with keys it
-- generated, which says nothing about whether a real issuer's documents, keys
-- and tokens are shaped the way the library expects. Here an issuer runs on
-- the network, holds a password, signs with a key of its own, and publishes
-- that key where the library goes looking for it.
module OIDC.E2E (oidcE2E) where

import qualified Data.ByteString as SB
import Data.IORef
import Data.List.NonEmpty (NonEmpty (..))
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TE
import Data.Time
import Network.HTTP.Client
import OIDC
import OIDC.E2E.Issuer
import OIDC.E2E.OptParse
import Test.Syd
import Test.Syd.OptParse (defaultSettings)

oidcE2E :: IO ()
oidcE2E = do
  settings <- getE2ESettings
  man <- newManager defaultManagerSettings
  sydTestWith defaultSettings (e2eSpec man settings)

e2eSpec :: Manager -> E2ESettings -> Spec
e2eSpec man E2ESettings {..} = do
  let issuer = Issuer e2eSettingIssuer

  -- The audience is the client a token was minted for, which is how dex and
  -- every other issuer name the service a token is meant for.
  let verification =
        verificationFor issuer (Audience e2eSettingClientId) (EdDSA :| [RS256])

  let federationFor :: [Verification] -> IO Federation
      federationFor verifications = case verificationsByIssuer verifications of
        Left duplicate ->
          expectationFailure (unwords ["Configured twice:", show (unIssuer duplicate)])
        Right byIssuer -> newFederation byIssuer

  -- Where this issuer says its keys are, asked of the issuer rather than
  -- configured, which is the whole point of discovery.
  let jwksURL :: IO Text
      jwksURL = do
        body <- fetchDiscoveryDocument man issuer
        case parseDiscovery issuer body of
          Left err -> expectationFailure err
          Right discovery -> pure (discoveryJWKSURL discovery)

  -- Counted, so that a test can say the keys came from the issuer over the
  -- network rather than from anywhere this test knew in advance.
  let countedFetch :: Text -> IO (IORef Int, Issuer -> IO (Maybe [JWK]))
      countedFetch url = do
        asked <- newIORef (0 :: Int)
        pure
          ( asked,
            \_ -> do
              modifyIORef' asked (+ 1)
              fetchJWKSet man url
          )

  let tokenFor :: (Text, Text) -> IO SB.ByteString
      tokenFor client =
        fetchIDToken
          man
          e2eSettingIssuer
          client
          e2eSettingRedirectURI
          (e2eSettingUsername, e2eSettingPassword)

  let aToken :: IO SB.ByteString
      aToken = tokenFor (e2eSettingClientId, e2eSettingClientSecret)

  let refusalIn :: Outcome -> Maybe String
      refusalIn = \case
        Refused refusal -> Just (renderRefusal refusal)
        NotFederated -> Nothing
        Accepted _ -> Nothing

  describe "parseDiscovery" $ do
    it "reads the document this issuer actually serves" $ do
      body <- fetchDiscoveryDocument man issuer
      case parseDiscovery issuer body of
        Left err -> expectationFailure err
        Right discovery -> do
          discoveryIssuer discovery `shouldBe` issuer
          -- Where the keys are has to be a url this test can then fetch, and
          -- the issuer has to admit to at least one algorithm the library
          -- will accept, or nothing it signs could ever be believed.
          discoveryJWKSURL discovery `shouldSatisfy` ("http" `Text.isPrefixOf`)
          discoveryAlgorithms discovery `shouldNotBe` []

    -- A document is only evidence about the issuer that served it.
    it "refuses that document as evidence about another issuer" $ do
      body <- fetchDiscoveryDocument man issuer
      parseDiscovery (Issuer "http://elsewhere.example.com") body
        `shouldSatisfy` \case
          Left _ -> True
          Right _ -> False

  describe "authenticate" $ do
    it "accepts a token this issuer really signed" $ do
      url <- jwksURL
      token <- aToken
      federation <- federationFor [verification]
      (asked, fetch) <- countedFetch url
      now <- getCurrentTime
      outcome <- authenticate fetch federation now token
      case outcome of
        Accepted claims -> do
          claimsIssuer claims `shouldBe` issuer
          claimsAudiences claims `shouldBe` [Audience e2eSettingClientId]
          -- The issuer decides what a subject looks like, so this says there
          -- is one rather than what it says.
          claimsSubject claims `shouldNotBe` ""
          -- This issuer was configured to mint short-lived tokens, and a
          -- token nobody bounded the lifetime of is not one.
          claimsLifetime claims `shouldSatisfy` (\lifetime -> lifetime > 0 && lifetime <= 600)
        other ->
          expectationFailure (unwords ["Expected a token to be accepted, got", show other])
      -- Fetched from the issuer, exactly once.
      readIORef asked `shouldReturn` 1

    it "asks the issuer for its keys once across several tokens" $ do
      url <- jwksURL
      federation <- federationFor [verification]
      (asked, fetch) <- countedFetch url
      now <- getCurrentTime
      first <- aToken
      second <- aToken
      _ <- authenticate fetch federation now first
      _ <- authenticate fetch federation now second
      readIORef asked `shouldReturn` 1

    -- Minted by the same issuer, with the same key, for somebody else. The
    -- audience is the only thing that tells the two apart, and without it a
    -- token meant for one service is a credential at every other.
    it "refuses a token this issuer minted for another client" $ do
      url <- jwksURL
      token <- tokenFor (e2eSettingOtherClientId, e2eSettingOtherClientSecret)
      federation <- federationFor [verification]
      (_, fetch) <- countedFetch url
      now <- getCurrentTime
      outcome <- authenticate fetch federation now token
      refusalIn outcome `shouldBe` Just "the token does not verify: JWTNotInAudience"

    it "says nothing about a token from an issuer it does not federate with" $ do
      url <- jwksURL
      token <- aToken
      federation <-
        federationFor
          [ verificationFor
              (Issuer "http://elsewhere.example.com")
              (Audience "whoever")
              (EdDSA :| [])
          ]
      (asked, fetch) <- countedFetch url
      now <- getCurrentTime
      authenticate fetch federation now token `shouldReturn` NotFederated
      -- An issuer nobody federates with cannot be made to cost a request.
      readIORef asked `shouldReturn` 0

    it "refuses a token whose signature was tampered with" $ do
      url <- jwksURL
      token <- aToken
      -- The last segment is the signature. Changing one of its characters
      -- leaves a token the issuer would recognise the shape of and did not
      -- sign.
      tampered <- case Text.splitOn "." (TE.decodeUtf8Lenient token) of
        [header, payload, signature] ->
          pure $
            TE.encodeUtf8 $
              Text.intercalate "." [header, payload, Text.cons (flipFirst signature) (Text.drop 1 signature)]
        _ -> expectationFailure "A signed token has three segments."
      federation <- federationFor [verification]
      (_, fetch) <- countedFetch url
      now <- getCurrentTime
      outcome <- authenticate fetch federation now tampered
      refusalIn outcome `shouldBe` Just "the token does not verify: JWSError JWSInvalidSignature"

    -- This issuer mints short-lived tokens, so a clock far enough ahead is
    -- the same thing as waiting for one to expire.
    it "refuses a token that has expired" $ do
      url <- jwksURL
      token <- aToken
      federation <- federationFor [verification]
      (_, fetch) <- countedFetch url
      now <- getCurrentTime
      outcome <- authenticate fetch federation (addUTCTime (24 * 3600) now) token
      refusalIn outcome `shouldBe` Just "the token does not verify: JWTExpired"

    it "refuses a token signed with an algorithm this issuer may not use" $ do
      url <- jwksURL
      token <- aToken
      -- Ed25519 only, which this issuer does not sign with, so the signature
      -- it did make is one the library will not look at.
      federation <- federationFor [verification {verificationAlgorithms = EdDSA :| []}]
      (_, fetch) <- countedFetch url
      now <- getCurrentTime
      outcome <- authenticate fetch federation now token
      refusalIn outcome `shouldBe` Just "the token does not verify: JWSError JWSNoSignatures"

-- | A character that is not the one a segment starts with, and is still part
-- of the base64url alphabet, so that what fails is the signature rather than
-- the decoding.
flipFirst :: Text -> Char
flipFirst segment = case Text.uncons segment of
  Just ('A', _) -> 'B'
  _ -> 'A'
