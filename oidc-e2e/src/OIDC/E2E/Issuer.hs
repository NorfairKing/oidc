{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

-- | Getting a token out of a real OpenID Connect issuer, the way a client
-- does.
--
-- None of this is "OIDC"'s: a resource server is handed a token that somebody
-- else went and got. It is here because a test of the library has to get a
-- real one from somewhere, and a real one means an issuer that checked a
-- password and signed with a key of its own.
module OIDC.E2E.Issuer
  ( fetchIDToken,
    fetchDiscoveryDocument,
    fetchJWKSet,
  )
where

import Control.Monad (when)
import qualified Data.Aeson as JSON
import Data.Aeson.Types (parseEither)
import qualified Data.ByteString as SB
import qualified Data.ByteString.Lazy as LB
import Data.List (find)
import Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as TE
import Network.HTTP.Client
import Network.HTTP.Types (hLocation, statusCode)
import Network.URI (parseURIReference, relativeTo)
import OIDC
import OIDC.E2E.OptParse (E2EGrant (..), renderE2EGrant)

-- | The document an issuer publishes about itself, as it served it.
--
-- Fetched here and parsed by the library, so that what is tested is the
-- library reading a real issuer's answer rather than one written here.
fetchDiscoveryDocument :: Manager -> Issuer -> IO LB.ByteString
fetchDiscoveryDocument man issuer = do
  request <- parseRequest (Text.unpack (discoveryURL issuer))
  responseBody <$> httpLbs request man

fetchJWKSet :: Manager -> Text -> IO (Maybe [JWK])
fetchJWKSet man url = do
  request <- parseRequest (Text.unpack url)
  response <- httpLbs request man
  case parseJWKSet (responseBody response) of
    Left _ -> pure Nothing
    Right keys -> pure (Just keys)

-- | A token the issuer minted for this client, about the workload whose
-- credentials it checked.
--
-- Which grant to use is the issuer's business rather than the library's: dex
-- offers only the authorization code flow, Keycloak also takes the
-- credentials straight. What comes out either way is a short-lived JWT the
-- issuer signed, naming this client as its audience.
fetchIDToken ::
  Manager ->
  E2EGrant ->
  -- | Issuer
  Text ->
  -- | Client id and secret
  (Text, Text) ->
  -- | Redirect uri
  Text ->
  -- | Username and password
  (Text, Text) ->
  IO SB.ByteString
fetchIDToken man grant issuer client@(clientId, clientSecret) redirectURI credentials = do
  tokenEndpoint <- discoverEndpoint man issuer "token_endpoint"
  body <- case grant of
    GrantDirectAccess ->
      pure
        [ ("grant_type", "password"),
          ("username", TE.encodeUtf8 (fst credentials)),
          ("password", TE.encodeUtf8 (snd credentials)),
          -- Without this the issuer answers with an access token and no id
          -- token, and an id token is what names this client as its
          -- audience.
          ("scope", "openid")
        ]
    GrantAuthorizationCode -> do
      authorizationEndpoint <- discoverEndpoint man issuer "authorization_endpoint"
      code <- fetchAuthorizationCode man authorizationEndpoint clientId redirectURI credentials
      pure
        [ ("grant_type", "authorization_code"),
          ("code", TE.encodeUtf8 code),
          ("redirect_uri", TE.encodeUtf8 redirectURI)
        ]
  request <- parseRequest (Text.unpack tokenEndpoint)
  response <-
    httpLbs
      ( applyBasicAuth
          (TE.encodeUtf8 clientId)
          (TE.encodeUtf8 clientSecret)
          (urlEncodedBody body request)
      )
      man
  case JSON.eitherDecode (responseBody response) of
    Left err ->
      fail $
        unwords
          [ "The issuer's answer to a",
            renderE2EGrant grant,
            "request as",
            concat [show (fst client), ":"],
            err
          ]
    Right value -> case parseEither (JSON.withObject "token response" (JSON..: "id_token")) value of
      Left err ->
        fail $
          unwords
            [ "The issuer's token response holds no id token:",
              concat [err, ","],
              "in",
              show (LB.toStrict (responseBody response))
            ]
      Right idToken -> pure (TE.encodeUtf8 idToken)

-- | Read one endpoint out of the issuer's discovery document.
discoverEndpoint :: Manager -> Text -> JSON.Key -> IO Text
discoverEndpoint man issuer key = do
  request <- parseRequest (Text.unpack (discoveryURL (Issuer issuer)))
  response <- httpLbs request man
  case JSON.eitherDecode (responseBody response) of
    Left err -> fail (unwords ["The issuer's discovery document is not JSON:", err])
    Right value -> case parseEither (JSON.withObject "discovery document" (JSON..: key)) value of
      Left err ->
        fail (unwords ["The issuer's discovery document holds no", show @JSON.Key key, concat [":", err]])
      Right endpoint -> pure endpoint

-- | The code the issuer hands out once it has decided who is asking.
--
-- Followed by hand rather than by the manager, because the last redirect goes
-- to a url nothing is listening on, and it is the only one whose destination
-- this wants to read.
fetchAuthorizationCode :: Manager -> Text -> Text -> Text -> (Text, Text) -> IO Text
fetchAuthorizationCode man authorizationEndpoint clientId redirectURI (username, password) = do
  request <- parseRequest (Text.unpack authorizationEndpoint)
  let authorizationRequest =
        setQueryString
          [ ("client_id", Just (TE.encodeUtf8 clientId)),
            ("response_type", Just "code"),
            ("scope", Just "openid email"),
            ("redirect_uri", Just (TE.encodeUtf8 redirectURI)),
            ("state", Just "oidc-e2e")
          ]
          request {redirectCount = 0}
  go (5 :: Int) authorizationRequest
  where
    go :: Int -> Request -> IO Text
    go redirectsLeft request = do
      when (redirectsLeft <= 0) $
        fail "The issuer redirected more times than any authorization flow should."
      response <- httpNoBody request man
      case lookup hLocation (responseHeaders response) of
        Nothing ->
          fail $
            unwords
              [ "The issuer answered",
                show @Int (statusCode (responseStatus response)),
                "without sending anywhere, so there is no authorization code to read."
              ]
        Just location -> do
          let locationText = TE.decodeUtf8Lenient location
          case authorizationCodeIn locationText of
            Just code -> pure code
            -- Resolved against the request it came from, because an issuer
            -- sends the hops within itself as paths rather than as urls.
            Nothing -> case parseURIReference (Text.unpack locationText) of
              Nothing ->
                fail $
                  unwords ["The issuer sent somewhere that is not a url:", show @Text locationText]
              Just uri -> do
                next <- requestFromURI (uri `relativeTo` getUri request)
                go (redirectsLeft - 1) (signingIn next {redirectCount = 0})

    -- \| Sign in, if this is the hop the issuer asks for credentials at.
    --
    -- Recognised by the url the issuer sent rather than by reading the form it
    -- would serve there, so this does not depend on the issuer's HTML.
    signingIn :: Request -> Request
    signingIn request
      | "/login" `SB.isSuffixOf` path request =
          urlEncodedBody
            [ ("login", TE.encodeUtf8 username),
              ("password", TE.encodeUtf8 password)
            ]
            request
      | otherwise = request

-- | The @code@ query parameter of a url, if it has one.
authorizationCodeIn :: Text -> Maybe Text
authorizationCodeIn location = do
  query <- case Text.splitOn "?" location of
    [_, query] -> Just query
    _ -> Nothing
  parameter <- find ("code=" `Text.isPrefixOf`) (Text.splitOn "&" query)
  Text.stripPrefix "code=" parameter
