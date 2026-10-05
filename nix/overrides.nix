{ lib
, haskell
, ...
}:

self: _:
with lib;
with haskell.lib;

let
  # A default build, with two exceptions.
  #
  # buildFromSdist, so that what is built is what would be published: a file
  # the cabal file forgot to list fails here rather than on Hackage.
  #
  # -Werror here rather than in the cabal files, so that a warning a later GHC
  # invents fails this build and not the build of whoever depends on this.
  oidcPkg =
    name:
    buildFromSdist (
      appendConfigureFlag (self.callPackage (../${name}) { }) "--ghc-options=-Werror"
    );

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
