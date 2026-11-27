package io.phasetwo.keycloak.kms.aws.credentials;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsCredentialsProvider;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.testsupport.StubServer;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** STS AssumeRole on top of the server's own credentials, against a stub STS. */
class AssumeRoleCredentialsProviderTest {

  private static final String ROLE = "arn:aws:iam::444455556666:role/phasetwo-keycloak-kms";

  private static final String STS_OK =
      """
      <AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
        <AssumeRoleResult>
          <AssumedRoleUser>
            <Arn>arn:aws:sts::444455556666:assumed-role/phasetwo-keycloak-kms/keycloak-kms</Arn>
          </AssumedRoleUser>
          <Credentials>
            <AccessKeyId>ASIAASSUMED</AccessKeyId>
            <SecretAccessKey>assumed-secret</SecretAccessKey>
            <SessionToken>assumed-token</SessionToken>
            <Expiration>2030-06-01T12:00:00Z</Expiration>
          </Credentials>
        </AssumeRoleResult>
      </AssumeRoleResponse>
      """;

  private static AwsCredentialsProvider base() {
    return new AwsCredentialsProviderChain(
        List.of(new StaticCredentialsProvider("AKIABASE", "base-secret", null)));
  }

  private static AssumeRoleCredentialsProvider provider(
      AwsCredentialsProvider base, String externalId, String sessionName, String endpoint) {
    return new AssumeRoleCredentialsProvider(
        base, ROLE, externalId, sessionName, 0, "eu-central-1", endpoint);
  }

  @Test
  @DisplayName("assumes the role with a SigV4 request signed by the base credentials")
  void happyPath() throws Exception {
    try (StubServer sts = new StubServer()) {
      sts.route("/", STS_OK);
      AwsCredentials c = provider(base(), "ext-123", null, sts.baseUrl()).resolveOrNull();

      assertNotNull(c);
      assertEquals("ASIAASSUMED", c.accessKeyId());
      assertEquals("assumed-token", c.sessionToken());
      assertEquals(Instant.parse("2030-06-01T12:00:00Z"), c.expiration());
      assertEquals("assume-role", c.source());

      StubServer.Request r = sts.lastRequestTo("/");
      assertEquals("POST", r.method());
      assertTrue(r.body().contains("Action=AssumeRole&"));
      assertTrue(r.body().contains("RoleArn=" + ROLE.replace(":", "%3A").replace("/", "%2F")));
      assertTrue(r.body().contains("RoleSessionName=keycloak-kms"));
      assertTrue(r.body().contains("DurationSeconds=3600"));
      assertTrue(r.body().contains("ExternalId=ext-123"));

      String auth = r.headers().get("authorization");
      assertNotNull(auth, "AssumeRole must be signed");
      assertTrue(auth.startsWith("AWS4-HMAC-SHA256 Credential=AKIABASE/"), auth);
      assertTrue(auth.contains("/eu-central-1/sts/aws4_request"), auth);
      assertNotNull(r.headers().get("x-amz-date"));
    }
  }

  @Test
  @DisplayName("sends no ExternalId when none is configured, and the given session name")
  void noExternalId() throws Exception {
    try (StubServer sts = new StubServer()) {
      sts.route("/", STS_OK);
      provider(base(), " ", "intelcom-dev", sts.baseUrl()).resolveOrNull();
      String body = sts.lastRequestTo("/").body();
      assertFalse(body.contains("ExternalId"));
      assertTrue(body.contains("RoleSessionName=intelcom-dev"));
    }
  }

  @Test
  @DisplayName("passes temporary base credentials' session token to STS")
  void temporaryBase() throws Exception {
    try (StubServer sts = new StubServer()) {
      sts.route("/", STS_OK);
      AwsCredentialsProvider base =
          new AwsCredentialsProviderChain(
              List.of(new StaticCredentialsProvider("ASIABASE", "base-secret", "base-token")));
      provider(base, null, null, sts.baseUrl()).resolveOrNull();
      assertEquals("base-token", sts.lastRequestTo("/").headers().get("x-amz-security-token"));
    }
  }

  @Test
  @DisplayName("a refused AssumeRole names the role and the identity that tried")
  void refused() throws Exception {
    try (StubServer sts = new StubServer()) {
      sts.route(
          "/",
          403,
          "<ErrorResponse><Error><Code>AccessDenied</Code><Message>not authorized"
              + "</Message></Error></ErrorResponse>");
      KmsException e =
          assertThrows(
              KmsException.class,
              () -> provider(base(), "ext-123", null, sts.baseUrl()).resolveOrNull());
      assertTrue(e.getMessage().contains(ROLE), e.getMessage());
      assertTrue(e.getMessage().contains("HTTP 403"), e.getMessage());
      assertTrue(e.getMessage().contains("static-config"), e.getMessage());
      assertTrue(e.getMessage().contains("external id"), e.getMessage());
    }
  }

  @Test
  @DisplayName("with no base identity it fails loudly rather than returning nothing")
  void noBase() {
    AwsCredentialsProvider none =
        new AwsCredentialsProviderChain(List.of(new StaticCredentialsProvider(null, null, null)));
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> provider(none, null, null, "http://127.0.0.1:1").resolveOrNull());
    assertTrue(e.getMessage().contains("no AWS identity to assume it with"), e.getMessage());
  }

  @Test
  @DisplayName("the chain's error carries the STS refusal, not a generic 'no credentials'")
  void chainSurfacesReason() throws Exception {
    try (StubServer sts = new StubServer()) {
      sts.route(
          "/", 403, "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>");
      AwsCredentialsProviderChain chain =
          new AwsCredentialsProviderChain(List.of(provider(base(), null, null, sts.baseUrl())));
      KmsException e = assertThrows(KmsException.class, chain::resolve);
      assertTrue(
          e.getMessage().contains("assume-role: STS AssumeRole for " + ROLE), e.getMessage());
    }
  }

  @Test
  @DisplayName("rejects session names and durations STS would reject")
  void validation() {
    assertThrows(KmsException.class, () -> provider(base(), null, "has space", null));
    assertThrows(
        KmsException.class,
        () ->
            new AssumeRoleCredentialsProvider(base(), ROLE, null, null, 60, "eu-central-1", null));
    assertThrows(
        IllegalArgumentException.class,
        () -> new AssumeRoleCredentialsProvider(base(), " ", null, null, 0, "eu-central-1", null));
  }

  @Test
  @DisplayName("describes the role and the base identity for the startup log")
  void describe() throws Exception {
    try (StubServer sts = new StubServer()) {
      sts.route("/", STS_OK);
      AssumeRoleCredentialsProvider p = provider(base(), null, null, sts.baseUrl());
      p.resolveOrNull();
      assertEquals("assume-role " + ROLE + " via static-config", p.describe());
    }
  }
}
