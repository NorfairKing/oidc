{
  description = "oidc";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    pre-commit-hooks.url = "github:cachix/pre-commit-hooks.nix";
    weeder-nix.url = "github:NorfairKing/weeder-nix";
    weeder-nix.flake = false;
    validity.url = "github:NorfairKing/validity";
    validity.flake = false;
    safe-coloured-text.url = "github:NorfairKing/safe-coloured-text";
    safe-coloured-text.flake = false;
    sydtest.url = "github:NorfairKing/sydtest";
    sydtest.flake = false;
    opt-env-conf.url = "github:NorfairKing/opt-env-conf";
    opt-env-conf.flake = false;
    hopinion.url = "github:NorfairKing/hopinion";
    hopinion.flake = false;
    release-to-hackage.url = "github:NorfairKing/release-to-hackage";
    marginalia.url = "github:NorfairKing/marginalia";
  };

  outputs =
    { self
    , nixpkgs
    , pre-commit-hooks
    , weeder-nix
    , validity
    , safe-coloured-text
    , sydtest
    , opt-env-conf
    , hopinion
    , marginalia
    , release-to-hackage
    }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        # The packages here are all rights reserved, which nixpkgs calls
        # unfree and refuses to evaluate without this.
        config.allowUnfree = true;
        overlays = [
          self.overlays.default
          (import (validity + "/nix/overlay.nix"))
          (import (safe-coloured-text + "/nix/overlay.nix"))
          (import (sydtest + "/nix/overlay.nix"))
          (import (opt-env-conf + "/nix/overlay.nix"))
          (import (weeder-nix + "/nix/overlay.nix"))
          (import (hopinion + "/nix/overlay.nix"))
        ];
      };
      # Only .nix files, and never the cabal2nix-generated ones, which the nix
      # linters have no say over.
      nixSources = pkgs.lib.cleanSourceWith {
        src = ./.;
        filter = path: type:
          let
            baseName = baseNameOf path;
          in
          (type == "directory" || pkgs.lib.hasSuffix ".nix" baseName) &&
          baseName != "default.nix";
      };
      haskellSources = name: pkgs.lib.cleanSourceWith {
        src = ./${name};
        filter = path: type:
          type == "directory" || pkgs.lib.hasSuffix ".hs" (baseNameOf path);
      };
    in
    {
      overlays.default = import ./nix/overlay.nix;
      packages.${system} = {
        default = pkgs.haskellPackages.oidc;
        # Uploads exactly those packages whose version is not on Hackage yet,
        # so a push that bumps no version releases nothing. Run from master
        # by the deploy job in nix-ci.nix.
        release-to-hackage = release-to-hackage.lib.${system}.makeHackageRelease {
          packages = pkgs.haskellPackages.oidcPackages;
        };
      };
      checks.${system} = {
        library = self.packages.${system}.default;
        tests = pkgs.haskellPackages.oidc-gen;
        # Everything else signs its own tokens with keys it generated. This
        # is the only check that says a real issuer's documents, keys and
        # tokens are shaped the way the library expects.
        e2e-test = pkgs.callPackage ./nix/e2e-test.nix {
          inherit (pkgs.testers) runNixOSTest;
          oidc-e2e = pkgs.haskell.lib.justStaticExecutables pkgs.haskellPackages.oidc-e2e;
        };
        shell = self.devShells.${system}.default;
        # Mutation testing over the one instrumented library. The test suite
        # lives in oidc-gen, so that package supplies the coverage rather than
        # being instrumented itself.
        mutation = pkgs.haskellPackages.sydtest.mutationCheck {
          name = "oidc";
          configFile = ./mutation.yaml;
          libraries = [ "oidc" ];
          tests = [ "oidc-gen" ];
        };
        weeder-check = pkgs.weeder-nix.makeWeederCheck {
          weederToml = ./weeder.toml;
          packages = builtins.attrNames pkgs.haskellPackages.oidcPackages;
        };
        hopinion = pkgs.hopinion.makeHopinionCheck {
          src = ./.;
          packages = builtins.attrNames pkgs.haskellPackages.oidcPackages;
        };
        hlint-check =
          let
            mkHlintCheck = name:
              pkgs.runCommand "hlint-check-${name}"
                {
                  nativeBuildInputs = [ pkgs.haskellPackages.hlint ];
                } ''
                hlint --hint=${./.hlint.yaml} ${haskellSources name}
                touch $out
              '';
          in
          pkgs.linkFarm "hlint-check" (builtins.listToAttrs (map
            (name: {
              name = "hlint-${name}";
              value = mkHlintCheck name;
            })
            (builtins.attrNames pkgs.haskellPackages.oidcPackages)));
        statix-check = pkgs.runCommand "statix-check"
          {
            nativeBuildInputs = [ pkgs.statix ];
          } ''
          statix check --config ${./statix.toml} ${nixSources}
          touch $out
        '';
        deadnix-check = pkgs.runCommand "deadnix-check"
          {
            nativeBuildInputs = [ pkgs.deadnix ];
          } ''
          cd ${nixSources}
          deadnix --fail .
          touch $out
        '';
        pre-commit = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            # Only formatters here. The linters are separate checks above, with
            # filtered sources, so that a formatting hook cannot block a commit
            # for a reason that is not formatting.
            hpack.enable = true;
            ormolu.enable = true;
            nixpkgs-fmt.enable = true;
            nixpkgs-fmt.excludes = [
              ".*/default.nix"
            ];
            cabal2nix.enable = true;
            tagref.enable = true;
            marginalia = {
              enable = true;
              name = "marginalia";
              description = "Show [check] annotations near changed lines";
              package = marginalia.packages.${system}.default;
              entry = "${marginalia.packages.${system}.default}/bin/marginalia --base development";
              language = "system";
              pass_filenames = false;
              stages = [ "pre-commit" ];
              verbose = true;
            };
          };
        };
      };
      devShells.${system}.default = pkgs.haskellPackages.shellFor {
        name = "oidc-shell";
        packages = p: builtins.attrValues p.oidcPackages;
        withHoogle = true;
        doBenchmark = true;
        buildInputs = with pkgs; [
          cabal-install
          git
          haskellPackages.weeder
          zlib
        ] ++ self.checks.${system}.pre-commit.enabledPackages;
        shellHook = self.checks.${system}.pre-commit.shellHook;
      };
    };
}
