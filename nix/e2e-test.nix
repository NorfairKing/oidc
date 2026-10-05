{ runNixOSTest
, lib
, writeText
, oidc-e2e
}:
let
  # Two issuers, because one issuer only ever says that the library agrees
  # with that issuer. dex and Keycloak are different implementations, sign
  # with different key types, and disagree about which grants they still
  # offer, so a suite that passes against both is one that is about OpenID
  # Connect rather than about dex.

  # The Keycloak realm is a checked-in file rather than one rendered from the
  # values below. Keycloak insists the file be named after the realm it holds,
  # and the module names what it imports after the basename of the path it is
  # given, which for a generated store path carries a string context that nix
  # will not allow in an attribute name. Everything both issuers have to agree
  # on is read back out of it, so there is still only one place any of it is
  # written down.
  # The realm says sslRequired none because the test network speaks plain
  # HTTP, and Keycloak otherwise refuses any request that did not come from
  # localhost. It also takes no fields it does not know, so the explanation is
  # here rather than in the file.
  keycloakRealm = builtins.fromJSON (builtins.readFile ./oidc-e2e-realm.json);
  keycloakRealmName = keycloakRealm.realm;
  firstClient = builtins.elemAt keycloakRealm.clients 0;
  secondClient = builtins.elemAt keycloakRealm.clients 1;
  theUser = builtins.elemAt keycloakRealm.users 0;

  clientId = firstClient.clientId;
  clientSecret = firstClient.secret;
  # A second client of the same issuer, signed with the same key. The only
  # thing that tells its tokens from the first client's is the audience.
  otherClientId = secondClient.clientId;
  otherClientSecret = secondClient.secret;
  # Nothing listens here. The authorization code comes out of the redirect
  # rather than out of a request to it.
  redirectURI = builtins.elemAt firstClient.redirectUris 0;
  password = (builtins.elemAt theUser.credentials 0).value;

  dexPort = 5556;
  dexIssuer = "http://dex:${toString dexPort}/dex";
  # dex knows the workload by its email address, Keycloak by its username.
  dexUsername = theUser.email;
  # bcrypt of password, which is how dex stores one.
  dexPasswordHash = "$2y$10$sll2Q3cZp9FFSEYLaHTk8ucV.t9y34Y88ws8qCTAXkj4/sfPbxX5.";

  keycloakPort = 8080;
  keycloakBase = "http://keycloak:${toString keycloakPort}";
  keycloakIssuer = "${keycloakBase}/realms/${keycloakRealmName}";
  keycloakUsername = theUser.username;
  keycloakAdminPassword = "keycloak-admin-password";

  # What the driver needs that it cannot ask the issuer. The issuer url is
  # all that is strictly needed to check a token; the rest is what it takes
  # to get one to check in the first place.
  driverEnvironment = { issuer, username, grant }: {
    OIDC_E2E_ISSUER = issuer;
    OIDC_E2E_CLIENT_ID = clientId;
    OIDC_E2E_CLIENT_SECRET = clientSecret;
    OIDC_E2E_OTHER_CLIENT_ID = otherClientId;
    OIDC_E2E_OTHER_CLIENT_SECRET = otherClientSecret;
    OIDC_E2E_REDIRECT_URI = redirectURI;
    OIDC_E2E_USERNAME = username;
    OIDC_E2E_PASSWORD = password;
    OIDC_E2E_GRANT = grant;
  };

  runDriver = settings:
    lib.concatStringsSep " " (
      lib.mapAttrsToList (key: value: "${key}=${lib.escapeShellArg value}")
        (driverEnvironment settings)
      ++ [ "oidc-e2e" ]
    );
in
runNixOSTest {
  name = "oidc-e2e-test";
  nodes = {
    # A real OpenID Connect issuer: it holds the password, signs with a key of
    # its own, publishes that key, and describes itself at the well-known url.
    # Nothing here is a stand-in.
    dex = _: {
      services.dex = {
        enable = true;
        settings = {
          issuer = dexIssuer;
          # No database of its own: the keys and the sign-ins these tests make
          # do not have to outlive the process.
          storage.type = "memory";
          web.http = "0.0.0.0:${toString dexPort}";
          expiry.idTokens = "5m";
          oauth2.skipApprovalScreen = true;
          staticClients = [
            {
              id = clientId;
              name = "oidc end-to-end test";
              secret = clientSecret;
              redirectURIs = [ redirectURI ];
            }
            {
              id = otherClientId;
              name = "somebody else";
              secret = otherClientSecret;
              redirectURIs = [ redirectURI ];
            }
          ];
          # The issuer holds the workload's credentials itself, rather than
          # standing in front of something else that holds them, so the
          # sign-in these tests make is a real one.
          enablePasswordDB = true;
          staticPasswords = [
            {
              email = dexUsername;
              hash = dexPasswordHash;
              username = "workload";
              userID = "08a8684b-db88-4b73-90a9-3cd1661f5466";
            }
          ];
        };
      };
      networking.firewall.allowedTCPPorts = [ dexPort ];
    };
    keycloak = _: {
      # Keycloak is a JVM that brings a Postgres with it. CI on this
      # repository runs rarely, so the minutes are worth a second
      # implementation to disagree with.
      virtualisation.memorySize = 2048;
      services.keycloak = {
        enable = true;
        initialAdminPassword = keycloakAdminPassword;
        database.passwordFile = toString (writeText "keycloak-db-password" "keycloak-db-password");
        settings = {
          hostname = keycloakBase;
          http-enabled = true;
          http-host = "0.0.0.0";
          http-port = keycloakPort;
          hostname-strict = false;
        };
        realmFiles = [ ./oidc-e2e-realm.json ];
      };
      networking.firewall.allowedTCPPorts = [ keycloakPort ];
    };
    client = _: {
      environment.systemPackages = [ oidc-e2e ];
    };
  };
  testScript = ''
    start_all()

    dex.wait_for_unit("dex.service")
    dex.wait_for_open_port(${toString dexPort})
    keycloak.wait_for_unit("keycloak.service")
    keycloak.wait_for_open_port(${toString keycloakPort})
    client.wait_for_unit("multi-user.target")

    # Asked of each issuer before its suite runs, so that a failure in the
    # suite is about the library rather than about an issuer that is not up.
    client.wait_until_succeeds(
        "curl --fail --silent ${dexIssuer}/.well-known/openid-configuration > /dev/null"
    )
    client.wait_until_succeeds(
        "curl --fail --silent ${keycloakIssuer}/.well-known/openid-configuration > /dev/null"
    )

    with subtest("dex"):
        client.succeed("${runDriver { issuer = dexIssuer; username = dexUsername; grant = "authorization-code"; }} 2>&1 | tee /dev/stderr")

    with subtest("keycloak"):
        client.succeed("${runDriver { issuer = keycloakIssuer; username = keycloakUsername; grant = "direct-access"; }} 2>&1 | tee /dev/stderr")
  '';
}
