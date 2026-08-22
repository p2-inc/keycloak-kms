package io.phasetwo.keycloak.kms.aws;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.phasetwo.keycloak.kms.aws.credentials.StaticCredentialsProvider;
import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import io.phasetwo.keycloak.kms.testsupport.StubServer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The KMS wire protocol, against a stub that speaks it.
 *
 * <p>These check the shape of what we put on the wire and how we read what comes back — which is
 * the half LocalStack cannot check, since LocalStack is lenient about exactly the things a real KMS
 * is strict about, and cannot be made to return a throttling error on demand.
 */
class KmsApiTest {

  private static final ObjectMapper MAPPER = new ObjectMapper();

  private KmsApi apiFor(StubServer server) {
    return new KmsApi(
        new StaticCredentialsProvider("AKID", "secret", null), "us-east-1", server.baseUrl());
  }

  private static String b64(String s) {
    return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
  }

  private static JsonNode bodyOf(StubServer server) throws Exception {
    return MAPPER.readTree(server.lastRequestTo("/").body());
  }

  // ---------------------------------------------------------------- requests

  @Test
  @DisplayName("Encrypt sends the key, base64 plaintext and the encryption context")
  void encryptRequest() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route("/", "{\"CiphertextBlob\":\"" + b64("sealed") + "\"}");

      byte[] out =
          apiFor(server)
              .encrypt(
                  "alias/keys",
                  "material".getBytes(StandardCharsets.UTF_8),
                  EncryptionContext.forKey("realm-1", "kid-1", "RSA"));

      assertArrayEquals("sealed".getBytes(StandardCharsets.UTF_8), out);

      JsonNode req = bodyOf(server);
      assertEquals("alias/keys", req.get("KeyId").asText());
      assertEquals(b64("material"), req.get("Plaintext").asText());
      assertEquals("keycloak", req.get("EncryptionContext").get("app").asText());
      assertEquals("realm-1", req.get("EncryptionContext").get("realm").asText());
      assertEquals("kid-1", req.get("EncryptionContext").get("kid").asText());
      assertEquals("RSA", req.get("EncryptionContext").get("keyType").asText());

      assertEquals("TrentService.Encrypt", server.lastRequestTo("/").headers().get("x-amz-target"));
      assertEquals(
          "application/x-amz-json-1.1", server.lastRequestTo("/").headers().get("content-type"));
      assertTrue(
          server.lastRequestTo("/").headers().get("authorization").startsWith("AWS4-HMAC-SHA256"));
    }
  }

  @Test
  @DisplayName("Decrypt names the key as well as the ciphertext")
  void decryptNamesTheKey() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route("/", "{\"Plaintext\":\"" + b64("material") + "\"}");

      byte[] out =
          apiFor(server)
              .decrypt(
                  "alias/keys",
                  "sealed".getBytes(StandardCharsets.UTF_8),
                  EncryptionContext.forKey("realm-1", "kid-1", "RSA"));

      assertArrayEquals("material".getBytes(StandardCharsets.UTF_8), out);
      JsonNode req = bodyOf(server);
      // Passing KeyId on Decrypt is optional in the API but not optional for us: it stops a
      // ciphertext sealed under a different key in the same account from decrypting here.
      assertEquals("alias/keys", req.get("KeyId").asText());
      assertEquals(b64("sealed"), req.get("CiphertextBlob").asText());
      assertEquals("realm-1", req.get("EncryptionContext").get("realm").asText());
    }
  }

  @Test
  @DisplayName("Sign always uses MessageType=DIGEST and names the algorithm as KMS spells it")
  void signRequest() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route("/", "{\"Signature\":\"" + b64("der-signature") + "\"}");

      byte[] digest = new byte[32];
      byte[] sig =
          apiFor(server).sign("arn:aws:kms:::key/x", KmsSigningAlgorithm.ECDSA_SHA_256, digest);

      assertArrayEquals("der-signature".getBytes(StandardCharsets.UTF_8), sig);
      JsonNode req = bodyOf(server);
      assertEquals("DIGEST", req.get("MessageType").asText());
      assertEquals("ECDSA_SHA_256", req.get("SigningAlgorithm").asText());
      assertEquals(Base64.getEncoder().encodeToString(digest), req.get("Message").asText());
    }
  }

  @Test
  @DisplayName("an empty encryption context is omitted rather than sent as {}")
  void emptyContextOmitted() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route("/", "{\"CiphertextBlob\":\"" + b64("x") + "\"}");
      apiFor(server).encrypt("k", new byte[1], null);
      assertFalse(bodyOf(server).has("EncryptionContext"));
    }
  }

  // ---------------------------------------------------------------- responses

  @Test
  @DisplayName("DescribeKey reads the modern KeySpec field")
  void describeKeySpec() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route(
          "/",
          """
          {"KeyMetadata":{"Arn":"arn:aws:kms:us-east-1:111122223333:key/abc","KeyId":"abc",
           "KeySpec":"SYMMETRIC_DEFAULT","KeyUsage":"ENCRYPT_DECRYPT","Enabled":true}}
          """);
      KmsKeyDescription d = apiFor(server).describeKey("abc");
      assertEquals("arn:aws:kms:us-east-1:111122223333:key/abc", d.keyId());
      assertEquals("SYMMETRIC_DEFAULT", d.keySpec());
      assertTrue(d.isSymmetric());
      assertTrue(d.enabled());
    }
  }

  @Test
  @DisplayName("DescribeKey falls back to CustomerMasterKeySpec, which emulators still send")
  void describeLegacySpecField() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route(
          "/",
          """
          {"KeyMetadata":{"KeyId":"abc","CustomerMasterKeySpec":"ECC_NIST_P256",
           "KeyUsage":"SIGN_VERIFY","Enabled":true}}
          """);
      KmsKeyDescription d = apiFor(server).describeKey("abc");
      assertEquals("ECC_NIST_P256", d.keySpec());
      assertTrue(d.isEc());
      assertTrue(d.isSigning());
    }
  }

  @Test
  @DisplayName("a disabled key is reported as disabled, not as absent")
  void describeDisabled() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route(
          "/",
          "{\"KeyMetadata\":{\"KeyId\":\"abc\",\"KeySpec\":\"SYMMETRIC_DEFAULT\","
              + "\"KeyUsage\":\"ENCRYPT_DECRYPT\",\"Enabled\":false}}");
      assertFalse(apiFor(server).describeKey("abc").enabled());
    }
  }

  @Test
  @DisplayName("a response missing the field we need fails loudly")
  void missingField() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route("/", "{}");
      KmsException e =
          assertThrows(KmsException.class, () -> apiFor(server).encrypt("k", new byte[1], null));
      assertTrue(e.getMessage().contains("CiphertextBlob"), e.getMessage());
    }
  }

  // ---------------------------------------------------------------- errors

  @Test
  @DisplayName("AccessDenied is terminal and the message says what permission to look at")
  void accessDenied() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route(
          "/",
          400,
          "{\"__type\":\"AccessDeniedException\",\"message\":\"User is not authorized\"}");
      KmsException e =
          assertThrows(KmsException.class, () -> apiFor(server).encrypt("k", new byte[1], null));
      assertFalse(e.isRetryable(), "an IAM problem does not improve with retries");
      assertTrue(e.getMessage().contains("kms:Encrypt"), e.getMessage());
      assertTrue(e.getMessage().contains("EncryptionContext"), e.getMessage());
      assertEquals(1, server.requests().size(), "a terminal error must not be retried");
    }
  }

  @Test
  @DisplayName("a namespaced __type is unwrapped to the bare error name")
  void namespacedErrorType() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route(
          "/",
          400,
          "{\"__type\":\"com.amazonaws.kms#NotFoundException\",\"message\":\"Key not found\"}");
      KmsException e = assertThrows(KmsException.class, () -> apiFor(server).describeKey("nope"));
      assertTrue(e.getMessage().contains("NotFoundException"), e.getMessage());
      assertTrue(e.getMessage().contains("--spi-kms--aws--region"), e.getMessage());
    }
  }

  @Test
  @DisplayName("an invalid ciphertext points at the cross-environment restore case")
  void invalidCiphertext() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route("/", 400, "{\"__type\":\"IncorrectKeyException\",\"message\":\"nope\"}");
      KmsException e =
          assertThrows(KmsException.class, () -> apiFor(server).decrypt("k", new byte[1], null));
      assertTrue(e.getMessage().contains("another environment's database"), e.getMessage());
    }
  }

  @Test
  @DisplayName("throttling is retried and succeeds on a later attempt")
  void throttlingIsRetried() throws Exception {
    try (StubServer server = new StubServer()) {
      AtomicInteger n = new AtomicInteger();
      server.route(
          "/",
          (req, exchange) -> {
            if (n.incrementAndGet() < 3) {
              byte[] body =
                  "{\"__type\":\"ThrottlingException\",\"message\":\"slow down\"}"
                      .getBytes(StandardCharsets.UTF_8);
              try {
                exchange.sendResponseHeaders(400, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
              } catch (java.io.IOException e) {
                throw new RuntimeException(e);
              }
              return null;
            }
            return "{\"CiphertextBlob\":\"" + b64("sealed") + "\"}";
          });

      byte[] out = apiFor(server).encrypt("k", new byte[1], null);
      assertArrayEquals("sealed".getBytes(StandardCharsets.UTF_8), out);
      assertEquals(3, n.get());
    }
  }

  @Test
  @DisplayName("persistent throttling gives up after three attempts, still marked retryable")
  void throttlingGivesUp() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route("/", 400, "{\"__type\":\"ThrottlingException\",\"message\":\"slow down\"}");
      KmsException e =
          assertThrows(KmsException.class, () -> apiFor(server).encrypt("k", new byte[1], null));
      assertTrue(e.isRetryable());
      assertTrue(e.getMessage().contains("asymmetric operation quota"), e.getMessage());
      assertEquals(3, server.requests().size());
    }
  }

  @Test
  @DisplayName("a 5xx is retried even when the body says nothing useful")
  void serverErrorIsRetried() throws Exception {
    try (StubServer server = new StubServer()) {
      server.route("/", 503, "<html>gateway</html>");
      KmsException e =
          assertThrows(KmsException.class, () -> apiFor(server).encrypt("k", new byte[1], null));
      assertTrue(e.isRetryable());
      assertEquals(3, server.requests().size());
      assertTrue(e.getMessage().contains("gateway"), "the raw body beats a parse complaint");
    }
  }

  @Test
  @DisplayName("an unreachable endpoint is retryable, and names the endpoint")
  void unreachable() {
    KmsApi api =
        new KmsApi(
            new StaticCredentialsProvider("AKID", "secret", null),
            "us-east-1",
            "http://127.0.0.1:1");
    KmsException e = assertThrows(KmsException.class, () -> api.describeKey("k"));
    assertTrue(e.isRetryable());
    assertTrue(e.getMessage().contains("127.0.0.1:1"), e.getMessage());
  }

  @Test
  @DisplayName("the endpoint host, including a port, is what gets signed")
  void endpointPortIsSigned() throws Exception {
    // A LocalStack endpoint is host:port; signing bare 'host' would make every request fail
    // authentication in exactly the environment the integration tests run in.
    try (StubServer server = new StubServer()) {
      server.route("/", "{\"CiphertextBlob\":\"" + b64("x") + "\"}");
      apiFor(server).encrypt("k", new byte[1], null);
      String auth = server.lastRequestTo("/").headers().get("authorization");
      assertTrue(auth.contains("SignedHeaders=content-type;host;x-amz-date;x-amz-target"), auth);
    }
  }
}
