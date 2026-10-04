{ runNixOSTest
, oidc-e2e
}:
let
  issuerPort = 5556;
  # Exactly as the issuer names itself, which is what a token carries and what
  # the library compares against.
  issuerUrl = "http://issuer:${builtins.toString issuerPort}/dex";
  clientId = "oidc-e2e";
  clientSecret = "oidc-e2e-secret";
  # A second client of the same issuer, signed with the same key. The only
  # thing that tells its tokens from the first client's is the audience.
  otherClientId = "somebody-else";
  otherClientSecret = "somebody-else-secret";
  # Nothing listens here. The authorization code comes out of the redirect
  # rather than out of a request to it.
  redirectURI = "http://127.0.0.1:1/callback";
  # The workload the issuer knows. Its password is checked against the hash
  # below on every sign-in, so these tests fail if either is wrong.
  username = "workload@example.com";
  password = "workload-password";
  # bcrypt of password, which is how dex stores one.
  passwordHash = "$2y$10$sll2Q3cZp9FFSEYLaHTk8ucV.t9y34Y88ws8qCTAXkj4/sfPbxX5.";
in
runNixOSTest {
  name = "oidc-e2e-test";
  nodes = {
    # A real OpenID Connect issuer: it holds the password, signs with a key of
    # its own, publishes that key, and describes itself at the well-known url.
    # Nothing here is a stand-in.
    issuer = _: {
      services.dex = {
        enable = true;
        settings = {
          issuer = issuerUrl;
          # No database of its own: the keys and the sign-ins these tests make
          # do not have to outlive the process.
          storage.type = "memory";
          web.http = "0.0.0.0:${builtins.toString issuerPort}";
          # Short-lived, so that what the tests accept is a short-lived token
          # and the lifetime assertion is about something real.
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
              email = username;
              hash = passwordHash;
              username = "workload";
              userID = "08a8684b-db88-4b73-90a9-3cd1661f5466";
            }
          ];
        };
      };
      networking.firewall.allowedTCPPorts = [ issuerPort ];
    };
    client = _: {
      environment.systemPackages = [ oidc-e2e ];
      environment.variables = {
        OIDC_E2E_ISSUER = issuerUrl;
        OIDC_E2E_CLIENT_ID = clientId;
        OIDC_E2E_CLIENT_SECRET = clientSecret;
        OIDC_E2E_OTHER_CLIENT_ID = otherClientId;
        OIDC_E2E_OTHER_CLIENT_SECRET = otherClientSecret;
        OIDC_E2E_REDIRECT_URI = redirectURI;
        OIDC_E2E_USERNAME = username;
        OIDC_E2E_PASSWORD = password;
      };
    };
  };
  testScript = ''
    start_all()

    issuer.wait_for_unit("dex.service")
    issuer.wait_for_open_port(${builtins.toString issuerPort})
    client.wait_for_unit("multi-user.target")

    # Asked of the issuer before the suite runs, so that a failure in the
    # suite is about the library rather than about an issuer that is not up.
    client.succeed(
        "curl --fail --silent ${issuerUrl}/.well-known/openid-configuration > /dev/null"
    )

    client.succeed("oidc-e2e 2>&1 | tee /dev/stderr")
  '';
}
