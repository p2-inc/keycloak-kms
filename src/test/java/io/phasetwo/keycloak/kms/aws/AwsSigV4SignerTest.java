package io.phasetwo.keycloak.kms.aws;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Checks the signer against vectors produced by botocore.
 *
 * <p>The value of these tests is entirely in their provenance: nothing here encodes what we think
 * SigV4 says, only what an independent implementation actually produced. A test asserting our own
 * output would pass just as happily with the algorithm wrong.
 */
class AwsSigV4SignerTest {

  private static final DateTimeFormatter AMZ =
      DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);

  record Vector(
      String name,
      String region,
      String host,
      String target,
      String payload,
      String accessKeyId,
      String secretAccessKey,
      String sessionToken,
      String amzDate,
      String authorization) {
    @Override
    public String toString() {
      return name;
    }
  }

  static List<Vector> vectors() throws Exception {
    try (InputStream in =
        AwsSigV4SignerTest.class.getClassLoader().getResourceAsStream("sigv4-vectors.json")) {
      JsonNode root = new ObjectMapper().readTree(in);
      List<Vector> out = new ArrayList<>();
      for (JsonNode v : root.get("vectors")) {
        out.add(
            new Vector(
                v.get("name").asText(),
                v.get("region").asText(),
                v.get("host").asText(),
                v.get("target").asText(),
                v.get("payload").asText(),
                v.get("accessKeyId").asText(),
                v.get("secretAccessKey").asText(),
                v.get("sessionToken").asText(),
                v.get("amzDate").asText(),
                v.get("authorization").asText()));
      }
      return out;
    }
  }

  private static Map<String, String> signVector(Vector v) {
    AwsCredentials creds =
        new AwsCredentials(
            v.accessKeyId(),
            v.secretAccessKey(),
            v.sessionToken().isEmpty() ? null : v.sessionToken(),
            null,
            "test");
    Map<String, String> headers = new LinkedHashMap<>();
    headers.put("Content-Type", "application/x-amz-json-1.1");
    headers.put("X-Amz-Target", v.target());
    return AwsSigV4Signer.sign(
        creds,
        v.region(),
        "kms",
        v.host(),
        "/",
        headers,
        v.payload(),
        ZonedDateTime.parse(v.amzDate(), AMZ.withZone(ZoneOffset.UTC)));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("vectors")
  @DisplayName("matches botocore's Authorization header exactly")
  void matchesBotocore(Vector v) {
    assertEquals(v.authorization(), signVector(v).get("Authorization"));
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("vectors")
  @DisplayName("signs x-amz-date with the value it returns, so the two cannot drift apart")
  void dateHeaderIsConsistent(Vector v) {
    Map<String, String> signed = signVector(v);
    assertEquals(v.amzDate(), signed.get("x-amz-date"));
    assertTrue(signed.get("Authorization").contains(v.amzDate().substring(0, 8)));
  }

  @Test
  @DisplayName("temporary credentials put the session token in SignedHeaders, not just the request")
  void sessionTokenIsSigned() throws Exception {
    Vector withToken =
        vectors().stream().filter(v -> !v.sessionToken().isEmpty()).findFirst().orElseThrow();
    assertTrue(
        withToken.authorization().contains("x-amz-security-token"),
        "the reference vector should exercise the session-token path");
    Map<String, String> signed = signVector(withToken);
    assertEquals(withToken.sessionToken(), signed.get("x-amz-security-token"));
    assertTrue(signed.get("Authorization").contains("x-amz-security-token"));
  }

  @Test
  @DisplayName("long-lived credentials do not emit a session-token header")
  void noSessionTokenWhenLongLived() throws Exception {
    Vector plain =
        vectors().stream().filter(v -> v.sessionToken().isEmpty()).findFirst().orElseThrow();
    Map<String, String> signed = signVector(plain);
    assertFalse(signed.containsKey("x-amz-security-token"));
    assertFalse(signed.get("Authorization").contains("x-amz-security-token"));
  }

  @Test
  @DisplayName("the returned map is exactly what must be sent — signed headers plus Authorization")
  void returnsEverySignedHeader() throws Exception {
    Vector v = vectors().get(0);
    Map<String, String> signed = signVector(v);
    String signedHeaders = v.authorization().replaceAll(".*SignedHeaders=([^,]+),.*", "$1");
    for (String name : signedHeaders.split(";")) {
      assertTrue(signed.containsKey(name), "missing signed header: " + name);
    }
    assertTrue(signed.containsKey("Authorization"));
  }

  // ---- properties that no single vector can show ----

  @Test
  @DisplayName("a changed payload changes the signature")
  void payloadIsBound() throws Exception {
    Vector v = vectors().get(0);
    Vector tampered =
        new Vector(
            v.name(),
            v.region(),
            v.host(),
            v.target(),
            v.payload().replace("AQID", "AQIE"),
            v.accessKeyId(),
            v.secretAccessKey(),
            v.sessionToken(),
            v.amzDate(),
            v.authorization());
    assertNotEquals(v.authorization(), signVector(tampered).get("Authorization"));
  }

  @Test
  @DisplayName("a changed region changes the signature — a signing key is scoped to its region")
  void regionIsBound() throws Exception {
    Vector v = vectors().get(0);
    Vector other =
        new Vector(
            v.name(),
            "eu-central-1",
            v.host(),
            v.target(),
            v.payload(),
            v.accessKeyId(),
            v.secretAccessKey(),
            v.sessionToken(),
            v.amzDate(),
            v.authorization());
    assertNotEquals(v.authorization(), signVector(other).get("Authorization"));
  }

  @Test
  @DisplayName("a changed x-amz-target changes the signature, so an operation cannot be swapped")
  void targetIsBound() throws Exception {
    Vector v = vectors().get(0);
    Vector other =
        new Vector(
            v.name(),
            v.region(),
            v.host(),
            "TrentService.ScheduleKeyDeletion",
            v.payload(),
            v.accessKeyId(),
            v.secretAccessKey(),
            v.sessionToken(),
            v.amzDate(),
            v.authorization());
    assertNotEquals(v.authorization(), signVector(other).get("Authorization"));
  }

  @Test
  @DisplayName("a minute later is a different signature — replay windows are bounded")
  void timeIsBound() throws Exception {
    Vector v = vectors().get(0);
    AwsCredentials creds = AwsCredentials.longLived(v.accessKeyId(), v.secretAccessKey(), "test");
    Map<String, String> headers =
        Map.of("Content-Type", "application/x-amz-json-1.1", "X-Amz-Target", v.target());
    ZonedDateTime t = ZonedDateTime.parse(v.amzDate(), AMZ.withZone(ZoneOffset.UTC));
    String a =
        AwsSigV4Signer.sign(creds, v.region(), "kms", v.host(), "/", headers, v.payload(), t)
            .get("Authorization");
    String b =
        AwsSigV4Signer.sign(
                creds, v.region(), "kms", v.host(), "/", headers, v.payload(), t.plusMinutes(1))
            .get("Authorization");
    assertNotEquals(a, b);
  }

  @Test
  @DisplayName("header name case does not change the signature")
  void headerNamesAreCaseInsensitive() throws Exception {
    Vector v = vectors().get(0);
    AwsCredentials creds = AwsCredentials.longLived(v.accessKeyId(), v.secretAccessKey(), "test");
    ZonedDateTime t = ZonedDateTime.parse(v.amzDate(), AMZ.withZone(ZoneOffset.UTC));
    String lower =
        AwsSigV4Signer.sign(
                creds,
                v.region(),
                "kms",
                v.host(),
                "/",
                Map.of("content-type", "application/x-amz-json-1.1", "x-amz-target", v.target()),
                v.payload(),
                t)
            .get("Authorization");
    assertEquals(v.authorization(), lower);
  }

  @Test
  @DisplayName("the empty-payload hash is the well-known SHA-256 of the empty string")
  void emptyPayloadHash() {
    assertEquals(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        AwsSigV4Signer.sha256Hex(""));
  }
}
