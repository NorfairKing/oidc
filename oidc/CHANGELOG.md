# Changelog

## [Unreleased]

### Added

* `OIDC.Token`: verifying a token an issuer signed, and saying why one was
  refused.
* `OIDC.Provider`: the issuer, audiences, algorithms, maximum token lifetime
  and clock skew a token is checked against.
* `OIDC.Algorithm`: the signing algorithms, with no `none` and no `HS*`
  constructor.
* `OIDC.KeySet`: an issuer's published keys, fetched once under a lock and at
  most once a minute.
* `OIDC.Federation`: the whole check, against every issuer a service federates
  with.
* `OIDC.Discovery`: reading an issuer's discovery document.
