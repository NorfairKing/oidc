-- | Accepting a token an OpenID Connect issuer signed.
--
-- The resource server's half of OpenID Connect: something presents a token it
-- got from an issuer, and this says whether to believe it. The client's half,
-- getting a token in the first place, is not here.
--
-- A whole check reads:
--
-- 1. 'OIDC.Token.unverifiedIssuer' on the bearer token, to pick which
--    issuer's 'OIDC.Provider.Verification' and keys to use. Nothing read
--    there is trusted; it only chooses what to check against.
-- 2. 'OIDC.Token.decodeToken' and 'OIDC.Token.tokenKid'.
-- 3. 'OIDC.KeySet.verificationKey' for the key that @kid@ names, fetching the
--    issuer's key set if it is not held yet.
-- 4. 'OIDC.Token.verifyToken', which checks the signature, the issuer, the
--    audience, the clock and the token's lifetime, and hands back the claims.
--
-- What to do with those claims is the caller's: this library says who the
-- issuer vouched for, not what they may do.
module OIDC
  ( module OIDC.Algorithm,
    module OIDC.Provider,
    module OIDC.Token,
    module OIDC.KeySet,
    module OIDC.Federation,
    module OIDC.Discovery,
  )
where

import OIDC.Algorithm
import OIDC.Discovery
import OIDC.Federation
import OIDC.KeySet
import OIDC.Provider
import OIDC.Token
