{ lib
, haskell
, ...
}:

self: _:
with lib;
with haskell.lib;

let
  # A default build, made strict: built from an sdist, so a file the cabal
  # file forgot to list fails here rather than on Hackage, and with warnings
  # as errors, which stays out of the cabal files so that a warning a later
  # GHC invents fails this build and not the build of whoever depends on this.
  oidcPkg = name: buildStrictly (self.callPackage (../${name}) { });

  oidcPackages = {
    oidc = oidcPkg "oidc";
    # The generators and the test suite live here, so this is the package
    # whose checks run.
    oidc-gen = oidcPkg "oidc-gen";
    # The driver the NixOS test runs. Nothing depends on it.
    oidc-e2e = oidcPkg "oidc-e2e";
  };
in
{
  inherit oidcPackages;
}
  // oidcPackages
