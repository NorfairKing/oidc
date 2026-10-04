# oidc

Accept a token an OpenID Connect issuer signed.

This is the resource server's half of OpenID Connect: something presents a
token it got from an issuer, and this library says whether to believe it.
The client's half, getting a token in the first place, is not here; for that
see `oidc-client` or `openid-connect`.

The case it is for is workload identity federation. A workload that already
holds a short-lived token from an issuer you trust presents that token to your
API, instead of holding a credential of your issuing that it has to store,
rotate and revoke.

## What a check looks like

1. `unverifiedIssuer` on the bearer token, to pick which issuer's
   `Verification` and keys to check it against. Nothing read there is trusted;
   it only chooses what to check against.
2. `decodeToken` and `tokenKid`.
3. `verificationKey` for the key that `kid` names, fetching the issuer's key
   set if it is not held yet.
4. `verifyToken`, which checks the signature, the issuer, the audience, the
   clock and the token's lifetime, and hands back the claims.

What to do with those claims is yours: this library says who the issuer
vouched for, not what they may do.

## What it will not do

* **Verify an unsigned or symmetrically signed token.** `Algorithm` has no
  `none` constructor and no `HS*` constructor, so neither is something you can
  ask for. A symmetric key is the key that verifies as well as the key that
  signs, so an issuer that published one in a key set would have published the
  power to mint tokens.
* **Try every key the issuer publishes.** The key is the one the token's `kid`
  names, so a token whose header names one key and whose signature was made
  with another is refused rather than accepted on the strength of the second.
* **Make an HTTP request.** Fetching the key set and the discovery document is
  yours, which is what keeps an HTTP client, a retry policy and a logger out
  of this library, and lets a caller fetch through whatever it already has.
  `KeySet` holds the part that is easy to get wrong: one fetch at a time, a
  floor under how often an issuer is asked, and keeping the keys it has when a
  fetch fails.
