{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RecordWildCards #-}

module OIDC.E2E.OptParse
  ( getE2ESettings,
    E2ESettings (..),
    E2EGrant (..),
    parseE2EGrant,
    renderE2EGrant,
  )
where

import Data.List (find)
import Data.Text (Text)
import OptEnvConf
import Paths_oidc_e2e (version)

getE2ESettings :: IO E2ESettings
getE2ESettings = runSettingsParser version "Check oidc against a real OpenID Connect issuer."

-- | Everything about the issuer on the test network that this cannot ask it.
--
-- The issuer url is all that is strictly needed to check a token, because the
-- rest is discovered. The client and the workload are what it takes to get a
-- token to check in the first place, which is the part a real workload
-- already has done for it.
data E2ESettings = E2ESettings
  { e2eSettingIssuer :: !Text,
    e2eSettingClientId :: !Text,
    e2eSettingClientSecret :: !Text,
    -- | A second client of the same issuer, so that a token minted for
    -- somebody else is a real one rather than one this test made up.
    e2eSettingOtherClientId :: !Text,
    e2eSettingOtherClientSecret :: !Text,
    -- | Where the issuer sends the browser it thinks is doing this. Nothing
    -- listens there: the code comes out of the redirect rather than out of a
    -- request to it.
    e2eSettingRedirectURI :: !Text,
    e2eSettingUsername :: !Text,
    e2eSettingPassword :: !Text,
    -- | How to ask this issuer for a token.
    --
    -- Issuers differ in which grants they still offer, and this is about the
    -- issuers rather than about the library: what comes out either way is a
    -- JWT the issuer signed.
    e2eSettingGrant :: !E2EGrant
  }

-- | The ways the issuers on the test network will hand out a token.
data E2EGrant
  = -- | Sign in at the issuer's own login page and swap the code it
    -- redirects with. The only one dex still offers.
    GrantAuthorizationCode
  | -- | Post the credentials straight to the token endpoint. Keycloak calls
    -- this direct access grants; dex dropped it.
    GrantDirectAccess
  deriving (Enum, Bounded)

renderE2EGrant :: E2EGrant -> String
renderE2EGrant = \case
  GrantAuthorizationCode -> "authorization-code"
  GrantDirectAccess -> "direct-access"

parseE2EGrant :: String -> Maybe E2EGrant
parseE2EGrant rendered = find ((== rendered) . renderE2EGrant) [minBound .. maxBound]

instance HasParser E2ESettings where
  settingsParser = parseE2ESettings

parseE2ESettings :: Parser E2ESettings
parseE2ESettings = subEnv_ "oidc-e2e" $ withoutConfig $ do
  e2eSettingIssuer <-
    setting
      [ help "The issuer to check tokens against, exactly as it names itself",
        reader str,
        name "issuer",
        metavar "URL"
      ]
  e2eSettingClientId <-
    setting
      [ help "The client identifier to ask for a token as",
        reader str,
        name "client-id",
        metavar "CLIENT_ID"
      ]
  e2eSettingClientSecret <-
    setting
      [ help "The client secret to ask for a token with",
        reader str,
        name "client-secret",
        metavar "CLIENT_SECRET"
      ]
  e2eSettingOtherClientId <-
    setting
      [ help "A second client of the same issuer, to mint a token for somebody else",
        reader str,
        name "other-client-id",
        metavar "CLIENT_ID"
      ]
  e2eSettingOtherClientSecret <-
    setting
      [ help "That second client's secret",
        reader str,
        name "other-client-secret",
        metavar "CLIENT_SECRET"
      ]
  e2eSettingRedirectURI <-
    setting
      [ help "The redirect uri the issuer has registered for these clients",
        reader str,
        name "redirect-uri",
        metavar "URI"
      ]
  e2eSettingUsername <-
    setting
      [ help "The workload the issuer knows",
        reader str,
        name "username",
        metavar "USERNAME"
      ]
  e2eSettingPassword <-
    setting
      [ help "The password the issuer knows that workload by",
        reader str,
        name "password",
        metavar "PASSWORD"
      ]
  e2eSettingGrant <-
    setting
      [ help "How to ask this issuer for a token",
        reader (maybeReader parseE2EGrant),
        option,
        long "grant",
        env "GRANT",
        metavar "GRANT"
      ]
  pure E2ESettings {..}
