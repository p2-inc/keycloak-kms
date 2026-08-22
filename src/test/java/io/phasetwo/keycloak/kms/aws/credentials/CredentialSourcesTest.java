package io.phasetwo.keycloak.kms.aws.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.testsupport.StubServer;
import io.phasetwo.keycloak.kms.testsupport.TestEnvironment;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** Each credential source on its own, against a stub endpoint. */
class CredentialSourcesTest {

  @Nested
  class Static {

    @Test
    @DisplayName("returns what it was given")
    void present() {
      AwsCredentials c = new StaticCredentialsProvider("AKID", "secret", null).resolveOrNull();
      assertNotNull(c);
      assertEquals("AKID", c.accessKeyId());
      assertEquals("static-config", c.source());
    }

    @Test
    @DisplayName("a half-configured source is not a source")
    void partial() {
      assertNull(new StaticCredentialsProvider("AKID", "", null).resolveOrNull());
      assertNull(new StaticCredentialsProvider(null, "secret", null).resolveOrNull());
      assertNull(new StaticCredentialsProvider(null, null, null).resolveOrNull());
    }
  }

  @Nested
  class Env {

    @Test
    @DisplayName("reads the standard variables including the session token")
    void present() {
      AwsCredentials c =
          new EnvironmentCredentialsProvider(
                  new TestEnvironment()
                      .var("AWS_ACCESS_KEY_ID", "AKID")
                      .var("AWS_SECRET_ACCESS_KEY", "secret")
                      .var("AWS_SESSION_TOKEN", "token"))
              .resolveOrNull();
      assertNotNull(c);
      assertEquals("token", c.sessionToken());
    }

    @Test
    @DisplayName("absent variables mean 'not applicable', not an error")
    void absent() {
      assertNull(new EnvironmentCredentialsProvider(new TestEnvironment()).resolveOrNull());
      assertNull(
          new EnvironmentCredentialsProvider(new TestEnvironment().var("AWS_ACCESS_KEY_ID", "AKID"))
              .resolveOrNull());
    }
  }

  @Nested
  class Container {

    private static final String BODY =
        """
        {"AccessKeyId":"ASIACONTAINER","SecretAccessKey":"s3cr3t","Token":"tok",
         "Expiration":"2030-01-01T00:00:00Z"}
        """;

    @Test
    @DisplayName("ECS: resolves the relative URI against the link-local endpoint")
    void ecsRelativeUri() throws Exception {
      try (StubServer server = new StubServer()) {
        server.route("/v2/credentials/abc", BODY);
        AwsCredentials c =
            new ContainerCredentialsProvider(
                    new TestEnvironment()
                        .var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/abc"),
                    server.baseUrl())
                .resolveOrNull();
        assertNotNull(c);
        assertEquals("ASIACONTAINER", c.accessKeyId());
        assertEquals(Instant.parse("2030-01-01T00:00:00Z"), c.expiration());
      }
    }

    @Test
    @DisplayName("Pod Identity: sends the bearer token from the projected file")
    void podIdentitySendsAuthHeader() throws Exception {
      try (StubServer server = new StubServer()) {
        server.route("/v1/credentials", BODY);
        AwsCredentials c =
            new ContainerCredentialsProvider(
                    new TestEnvironment()
                        .var(
                            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                            server.baseUrl() + "/v1/credentials")
                        .var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/var/run/token")
                        .file("/var/run/token", "eyJhbGciOiJ.projected.token"))
                .resolveOrNull();
        assertNotNull(c);
        assertEquals(
            "eyJhbGciOiJ.projected.token",
            server.lastRequestTo("/v1/credentials").headers().get("authorization"),
            "Pod Identity credentials are only issued when the projected token is presented");
      }
    }

    @Test
    @DisplayName("Pod Identity: an unreadable token file is an error, not a silent skip")
    void podIdentityMissingTokenFile() {
      ContainerCredentialsProvider p =
          new ContainerCredentialsProvider(
              new TestEnvironment()
                  .var("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://127.0.0.1:1/x")
                  .var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "/nope"));
      KmsException e = assertThrows(KmsException.class, p::resolveOrNull);
      assertTrue(e.getMessage().contains("/nope"), e.getMessage());
    }

    @Test
    @DisplayName("no container variables means not applicable")
    void notApplicable() {
      assertNull(new ContainerCredentialsProvider(new TestEnvironment()).resolveOrNull());
    }

    @Test
    @DisplayName("a non-2xx from the endpoint is reported, not swallowed")
    void errorStatus() throws Exception {
      try (StubServer server = new StubServer()) {
        server.route("/v2/credentials/abc", 500, "boom");
        ContainerCredentialsProvider p =
            new ContainerCredentialsProvider(
                new TestEnvironment()
                    .var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/abc"),
                server.baseUrl());
        assertThrows(KmsException.class, p::resolveOrNull);
      }
    }
  }

  @Nested
  class WebIdentity {

    private static final String STS_OK =
        """
        <AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <AssumeRoleWithWebIdentityResult>
            <Credentials>
              <AccessKeyId>ASIAIRSA</AccessKeyId>
              <SecretAccessKey>irsa-secret</SecretAccessKey>
              <SessionToken>irsa-token</SessionToken>
              <Expiration>2030-06-01T12:00:00Z</Expiration>
            </Credentials>
          </AssumeRoleWithWebIdentityResult>
        </AssumeRoleWithWebIdentityResponse>
        """;

    private TestEnvironment env(String tokenFileContents) {
      TestEnvironment e =
          new TestEnvironment()
              .var("AWS_ROLE_ARN", "arn:aws:iam::111122223333:role/keycloak-kms")
              .var("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/sa-token")
              .var("AWS_REGION", "us-east-1");
      if (tokenFileContents != null) {
        e.file("/var/run/sa-token", tokenFileContents);
      }
      return e;
    }

    @Test
    @DisplayName("exchanges the projected token for credentials")
    void happyPath() throws Exception {
      try (StubServer server = new StubServer()) {
        server.route("/", STS_OK);
        AwsCredentials c =
            new WebIdentityCredentialsProvider(env("projected.jwt"), server.baseUrl())
                .resolveOrNull();
        assertNotNull(c);
        assertEquals("ASIAIRSA", c.accessKeyId());
        assertEquals("irsa-token", c.sessionToken());
        assertEquals(Instant.parse("2030-06-01T12:00:00Z"), c.expiration());
        assertEquals("web-identity", c.source());

        String body = server.lastRequestTo("/").body();
        assertTrue(body.contains("Action=AssumeRoleWithWebIdentity"));
        assertTrue(body.contains("WebIdentityToken=projected.jwt"));
        assertTrue(
            body.contains("RoleArn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fkeycloak-kms"));
      }
    }

    @Test
    @DisplayName("no role ARN means not applicable")
    void notApplicable() {
      assertNull(new WebIdentityCredentialsProvider(new TestEnvironment()).resolveOrNull());
    }

    @Test
    @DisplayName("a role ARN with no readable token names the actual problem")
    void tokenFileUnreadable() {
      KmsException e =
          assertThrows(
              KmsException.class,
              () ->
                  new WebIdentityCredentialsProvider(env(null), "http://127.0.0.1:1")
                      .resolveOrNull());
      assertTrue(e.getMessage().contains("projected token volume"), e.getMessage());
    }

    @Test
    @DisplayName("an STS rejection points at the trust policy")
    void stsRejects() throws Exception {
      try (StubServer server = new StubServer()) {
        server.route(
            "/", 403, "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>");
        KmsException e =
            assertThrows(
                KmsException.class,
                () ->
                    new WebIdentityCredentialsProvider(env("projected.jwt"), server.baseUrl())
                        .resolveOrNull());
        assertTrue(e.getMessage().contains("trust policy"), e.getMessage());
      }
    }

    @Test
    @DisplayName("the STS response parser does not resolve external entities")
    void xxeIsRefused() throws Exception {
      // If the parser expanded this, the credentials would contain the contents of /etc/passwd —
      // and more to the point, a DOCTYPE in a response we parse is never legitimate.
      String evil =
          """
          <?xml version="1.0"?>
          <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
          <AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>
            <AccessKeyId>&xxe;</AccessKeyId>
            <SecretAccessKey>s</SecretAccessKey>
          </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>
          """;
      try (StubServer server = new StubServer()) {
        server.route("/", evil);
        KmsException e =
            assertThrows(
                KmsException.class,
                () ->
                    new WebIdentityCredentialsProvider(env("projected.jwt"), server.baseUrl())
                        .resolveOrNull());
        assertTrue(e.getMessage().contains("parse"), e.getMessage());
      }
    }
  }

  @Nested
  class InstanceProfile {

    @Test
    @DisplayName("does the IMDSv2 token handshake and presents the token on every read")
    void imdsV2() throws Exception {
      try (StubServer server = new StubServer()) {
        server.route("/latest/api/token", "imds-token-value");
        server.route("/latest/meta-data/iam/security-credentials/", "keycloak-role\n");
        server.route(
            "/latest/meta-data/iam/security-credentials/keycloak-role",
            """
            {"AccessKeyId":"ASIAEC2","SecretAccessKey":"ec2-secret","Token":"ec2-token",
             "Expiration":"2030-01-01T00:00:00Z"}
            """);

        AwsCredentials c = new InstanceProfileCredentialsProvider(server.baseUrl()).resolveOrNull();
        assertNotNull(c);
        assertEquals("ASIAEC2", c.accessKeyId());
        assertEquals("instance-profile", c.source());

        assertEquals(
            "21600",
            server
                .lastRequestTo("/latest/api/token")
                .headers()
                .get("x-aws-ec2-metadata-token-ttl-seconds"));
        assertEquals("PUT", server.lastRequestTo("/latest/api/token").method());
        assertEquals(
            "imds-token-value",
            server
                .lastRequestTo("/latest/meta-data/iam/security-credentials/keycloak-role")
                .headers()
                .get("x-aws-ec2-metadata-token"),
            "IMDSv1 fallback would defeat the point of the handshake");
      }
    }

    @Test
    @DisplayName("no metadata service means not applicable, quickly and quietly")
    void notOnEc2() {
      long start = System.currentTimeMillis();
      // Port 1 refuses immediately; the point is that a miss returns null instead of throwing.
      assertNull(new InstanceProfileCredentialsProvider("http://127.0.0.1:1").resolveOrNull());
      assertTrue(System.currentTimeMillis() - start < 5_000, "a miss must not stall startup");
    }

    @Test
    @DisplayName("IMDS refusing the token handshake is a miss, not a crash")
    void tokenRefused() throws Exception {
      try (StubServer server = new StubServer()) {
        server.route("/latest/api/token", 403, "");
        assertNull(new InstanceProfileCredentialsProvider(server.baseUrl()).resolveOrNull());
      }
    }
  }

  @Nested
  class Expiry {

    @Test
    @DisplayName("credentials inside the refresh margin report as expiring")
    void refreshMargin() {
      AwsCredentials soon =
          new AwsCredentials("a", "b", "c", Instant.now().plusSeconds(60), "test");
      AwsCredentials later =
          new AwsCredentials("a", "b", "c", Instant.now().plusSeconds(3600), "test");
      assertTrue(soon.isExpiring(), "a token expiring in a minute must be refreshed before use");
      assertFalse(later.isExpiring());
      assertFalse(AwsCredentials.longLived("a", "b", "test").isExpiring());
    }

    @Test
    @DisplayName("toString never leaks the secret or the session token")
    void toStringIsSafe() {
      String s = new AwsCredentials("AKID", "SUPERSECRET", "SESSIONTOKEN", null, "test").toString();
      assertFalse(s.contains("SUPERSECRET"), s);
      assertFalse(s.contains("SESSIONTOKEN"), s);
      assertTrue(s.contains("AKID"));
    }
  }
}
