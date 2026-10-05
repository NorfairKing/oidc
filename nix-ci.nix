let
  system = "x86_64-linux";
in
{
  deploy = {
    release-to-hackage = {
      package = "packages.${system}.release-to-hackage";
      branches = [ "master" ];
      secrets = [ "HACKAGE_API_KEY" ];
    };
  };
}
