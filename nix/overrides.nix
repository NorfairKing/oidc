{ lib
, haskell
, ...
}:

self: _:
with lib;
with haskell.lib;

let
  oidcPkg =
    name:
    buildFromSdist (
      overrideCabal (self.callPackage (../${name}) { })
        (old: {
          doBenchmark = true;
          configureFlags = (old.configureFlags or [ ]) ++ [
            "--ghc-options=-Wall"
            "--ghc-options=-Wincomplete-uni-patterns"
            "--ghc-options=-Wincomplete-record-updates"
            "--ghc-options=-Wpartial-fields"
            "--ghc-options=-Widentities"
            "--ghc-options=-Wredundant-constraints"
            "--ghc-options=-Wcpp-undef"
            "--ghc-options=-Wunused-packages"
            "--ghc-options=-Werror"
          ];
        })
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
