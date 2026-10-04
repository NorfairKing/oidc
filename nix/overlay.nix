final: prev:
with final.lib;
with final.haskell.lib;
{
  haskellPackages = prev.haskellPackages.override (old: {
    overrides = composeExtensions (old.overrides or (_: _: { })) (self: _:
      let
        # These are duplicated in stack.yaml.
        oidcPkg = name:
          buildStrictly (overrideCabal
            (self.callPackage (../${name}) { })
            (oldAttrs: {
              configureFlags = (oldAttrs.configureFlags or [ ]) ++ [
                "--ghc-options=-O0"
                "--ghc-options=-fignore-interface-pragmas"
                "--ghc-options=-fomit-interface-pragmas"
                "--ghc-options=-Wincomplete-uni-patterns"
                "--ghc-options=-Wincomplete-record-updates"
                "--ghc-options=-Wpartial-fields"
                "--ghc-options=-Widentities"
                "--ghc-options=-Wredundant-constraints"
                "--ghc-options=-Wcpp-undef"
                "--ghc-options=-Wunused-packages"
              ];
              doBenchmark = false;
              doHaddock = false;
              doCoverage = false;
              doHoogle = false;
              hyperlinkSource = false;
              enableLibraryProfiling = false;
              enableExecutableProfiling = false;
              # These save time for the weeder build, which needs neither
              # optimised nor deployable binaries.
              dontStrip = true;
              enableDeadCodeElimination = false;
            }));

        oidcPackages = {
          oidc = oidcPkg "oidc";
          # The generators and the test suite live here, so this is the
          # package whose checks run.
          oidc-gen = oidcPkg "oidc-gen";
        };
      in
      {
        inherit oidcPackages;
      } // oidcPackages
    );
  });
}
