package io.phasetwo.keycloak.kms.aws;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.aws.credentials.StaticCredentialsProvider;
import io.phasetwo.keycloak.kms.keys.WrappedMaterial;
import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * The AWS backend against a real KMS API.
 *
 * <p>LocalStack rather than a mock, because the properties worth proving are the ones AWS enforces
 * and we merely ask for: that a mismatched encryption context is rejected, that a ciphertext does
 * not decrypt under the wrong key, and that a digest signed remotely verifies against the public
 * key locally. A stub would answer whatever we programmed it to.
 *
 * <p>It also exercises the whole hand-rolled stack end to end — SigV4, the credential chain, the
 * JSON protocol — against a server that actually parses it.
 */
class AwsKmsProviderIT {

  private static LocalStackContainer localstack;
  private static KmsApi api;
  private static AwsKmsProvider kms;

  private static String symmetricKey;
  private static String ecKey;
  private static String rsaKey;

  @BeforeAll
  static void startLocalStack() {
    io.phasetwo.keycloak.kms.testsupport.Crypto.init();
    localstack =
        new LocalStackContainer(DockerImageName.parse("localstack/localstack:3.8"))
            .withServices(LocalStackContainer.Service.KMS);
    localstack.start();

    api =
        new KmsApi(
            new StaticCredentialsProvider(
                localstack.getAccessKey(), localstack.getSecretKey(), null),
            localstack.getRegion(),
            localstack.getEndpoint().toString());
    kms = new AwsKmsProvider(api, null);

    symmetricKey = createKey("ENCRYPT_DECRYPT", "SYMMETRIC_DEFAULT");
    ecKey = createKey("SIGN_VERIFY", "ECC_NIST_P256");
    rsaKey = createKey("SIGN_VERIFY", "RSA_2048");
  }

  @AfterAll
  static void stopLocalStack() {
    if (localstack != null) {
      localstack.stop();
    }
  }

  /**
   * Provision a test key.
   *
   * <p>Done here rather than through {@link KmsApi} because {@code CreateKey} is deliberately not
   * part of this extension's surface — bring-your-own-key is a design decision, not an omission, so
   * adding a production method to make a test convenient would be the tail wagging the dog. It does
   * reuse {@link AwsSigV4Signer}, so the test's own plumbing is not a second implementation.
   */
  private static String createKey(String usage, String spec) {
    String payload = "{\"KeyUsage\":\"" + usage + "\",\"KeySpec\":\"" + spec + "\"}";
    java.net.URI endpoint = localstack.getEndpoint();
    String host =
        endpoint.getPort() > 0 ? endpoint.getHost() + ":" + endpoint.getPort() : endpoint.getHost();

    java.util.Map<String, String> headers =
        AwsSigV4Signer.sign(
            AwsCredentials.longLived(localstack.getAccessKey(), localstack.getSecretKey(), "test"),
            localstack.getRegion(),
            "kms",
            host,
            "/",
            java.util.Map.of(
                "Content-Type", "application/x-amz-json-1.1",
                "X-Amz-Target", "TrentService.CreateKey"),
            payload,
            java.time.ZonedDateTime.now(java.time.ZoneOffset.UTC));

    java.net.http.HttpRequest.Builder request =
        java.net.http.HttpRequest.newBuilder(endpoint)
            .POST(java.net.http.HttpRequest.BodyPublishers.ofString(payload));
    headers.forEach(
        (k, v) -> {
          if (!"host".equalsIgnoreCase(k)) {
            request.header(k, v);
          }
        });

    try {
      java.net.http.HttpResponse<String> response =
          java.net.http.HttpClient.newHttpClient()
              .send(request.build(), java.net.http.HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() / 100 != 2) {
        throw new IllegalStateException("CreateKey failed: " + response.body());
      }
      return new com.fasterxml.jackson.databind.ObjectMapper()
          .readTree(response.body())
          .get("KeyMetadata")
          .get("KeyId")
          .asText();
    } catch (java.io.IOException e) {
      throw new IllegalStateException("could not create a test key", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }

  private static EncryptionContext context(String realm, String kid, String type) {
    return EncryptionContext.forKey(realm, kid, type);
  }

  // ------------------------------------------------------------------ envelope

  @Test
  @DisplayName("material round-trips through a real KMS")
  void roundTrip() {
    byte[] material = "a realm private key".getBytes(StandardCharsets.UTF_8);
    EncryptionContext ctx = context("realm-a", "kid-1", "RSA");

    byte[] ciphertext = kms.encrypt(symmetricKey, material, ctx);
    assertFalse(new String(ciphertext, StandardCharsets.UTF_8).contains("realm private key"));
    assertArrayEquals(material, kms.decrypt(symmetricKey, ciphertext, ctx));
  }

  @Test
  @DisplayName("the whole storage format round-trips, not just the raw ciphertext")
  void storageFormatRoundTrips() {
    byte[] material = "material".getBytes(StandardCharsets.UTF_8);
    EncryptionContext ctx = context("realm-a", "kid-1", "HMAC");

    String stored = WrappedMaterial.encode(kms.encrypt(symmetricKey, material, ctx));
    assertTrue(stored.startsWith("kms://v1/"));
    assertArrayEquals(material, kms.decrypt(symmetricKey, WrappedMaterial.decode(stored), ctx));
  }

  @Test
  @DisplayName("AWS itself rejects a ciphertext lifted into another realm")
  void awsEnforcesTheEncryptionContext() {
    byte[] ciphertext =
        kms.encrypt(
            symmetricKey,
            "secret".getBytes(StandardCharsets.UTF_8),
            context("realm-a", "k", "RSA"));

    // This is the tenancy guarantee, and it is enforced by KMS rather than by our code.
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> kms.decrypt(symmetricKey, ciphertext, context("realm-b", "k", "RSA")));
    assertFalse(e.isRetryable());
    assertTrue(e.getMessage().contains("InvalidCiphertextException"), e.getMessage());
  }

  @Test
  @DisplayName("a ciphertext relabelled with another kid or key type is rejected too")
  void contextIsBoundFieldByField() {
    byte[] ciphertext =
        kms.encrypt(
            symmetricKey, "secret".getBytes(StandardCharsets.UTF_8), context("r", "kid-1", "RSA"));

    assertThrows(
        KmsException.class,
        () -> kms.decrypt(symmetricKey, ciphertext, context("r", "kid-2", "RSA")));
    assertThrows(
        KmsException.class,
        () -> kms.decrypt(symmetricKey, ciphertext, context("r", "kid-1", "HMAC")));
  }

  @Test
  @DisplayName("naming the wrong key on decrypt is refused, even within one account")
  void keyIdIsChecked() {
    String otherKey = createKey("ENCRYPT_DECRYPT", "SYMMETRIC_DEFAULT");
    byte[] ciphertext =
        kms.encrypt(
            symmetricKey, "secret".getBytes(StandardCharsets.UTF_8), context("r", "k", "AES"));

    KmsException e =
        assertThrows(
            KmsException.class, () -> kms.decrypt(otherKey, ciphertext, context("r", "k", "AES")));
    assertTrue(e.getMessage().contains("IncorrectKeyException"), e.getMessage());
    assertTrue(
        e.getMessage().contains("another environment's database"), "the hint should be there");
  }

  @Test
  @DisplayName("an RSA-4096 private key fits inside the 4 KB Encrypt limit")
  void largestRealisticMaterialFits() {
    // The one size question the design rests on: if PKCS#8 for the biggest key Keycloak offers did
    // not fit, envelope mode would need a data-key indirection instead of a direct Encrypt.
    byte[] pkcs8 =
        org.keycloak.common.util.KeyUtils.generateRsaKeyPair(4096).getPrivate().getEncoded();
    assertTrue(pkcs8.length < 4096, "PKCS#8 for RSA-4096 is " + pkcs8.length + " bytes");

    EncryptionContext ctx = context("r", "k", "RSA");
    assertArrayEquals(pkcs8, kms.decrypt(symmetricKey, kms.encrypt(symmetricKey, pkcs8, ctx), ctx));
  }

  // ------------------------------------------------------------------ metadata

  @Test
  @DisplayName("describe reports spec, usage and state")
  void describe() {
    KmsKeyDescription symmetric = kms.describe(symmetricKey);
    assertEquals("SYMMETRIC_DEFAULT", symmetric.keySpec());
    assertTrue(symmetric.isSymmetric());
    assertTrue(symmetric.enabled());

    KmsKeyDescription ec = kms.describe(ecKey);
    assertEquals("ECC_NIST_P256", ec.keySpec());
    assertTrue(ec.isSigning());
    assertTrue(ec.isEc());
  }

  @Test
  @DisplayName("a nonexistent key is a terminal error naming the region setting")
  void unknownKey() {
    KmsException e =
        assertThrows(
            KmsException.class, () -> kms.describe("00000000-0000-0000-0000-000000000000"));
    assertFalse(e.isRetryable());
    assertTrue(e.getMessage().contains("--spi-kms--aws--region"), e.getMessage());
  }

  // ------------------------------------------------------------------ native

  @Test
  @DisplayName("an EC digest signed by KMS verifies locally against the KMS public key")
  void ecSignVerify() throws Exception {
    PublicKey publicKey = kms.publicKey(ecKey);
    assertEquals("EC", publicKey.getAlgorithm());

    byte[] message = "a token".getBytes(StandardCharsets.UTF_8);
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(message);
    byte[] signature = kms.sign(ecKey, KmsSigningAlgorithm.ECDSA_SHA_256, digest);

    // Signing the digest must be indistinguishable from signing the message — the assumption the
    // whole MessageType=DIGEST design rests on.
    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(publicKey);
    verifier.update(message);
    assertTrue(verifier.verify(signature));
  }

  @ParameterizedTest
  @DisplayName("every RSA signing algorithm KMS offers verifies against the public key")
  @CsvSource({
    "RSASSA_PKCS1_V1_5_SHA_256, SHA256withRSA",
    "RSASSA_PKCS1_V1_5_SHA_384, SHA384withRSA",
    "RSASSA_PKCS1_V1_5_SHA_512, SHA512withRSA"
  })
  void rsaPkcs1SignVerify(String kmsAlgorithm, String javaAlgorithm) throws Exception {
    KmsSigningAlgorithm algorithm = KmsSigningAlgorithm.valueOf(kmsAlgorithm);
    byte[] message = "a token".getBytes(StandardCharsets.UTF_8);
    byte[] digest = MessageDigest.getInstance(algorithm.digestAlgorithm()).digest(message);

    byte[] signature = kms.sign(rsaKey, algorithm, digest);

    Signature verifier = Signature.getInstance(javaAlgorithm);
    verifier.initVerify(kms.publicKey(rsaKey));
    verifier.update(message);
    assertTrue(verifier.verify(signature));
  }

  /**
   * PSS signatures verify — and the salt length is recorded, because the emulator differs from AWS.
   *
   * <p>AWS documents a salt length equal to the digest length. LocalStack signs with the
   * <em>maximum</em> salt length instead. Both are well-formed PSS and both verify, so this asserts
   * the part the extension actually controls — that the right digest reaches the right algorithm —
   * and reports which salt length appeared rather than pretending the difference is not there.
   *
   * <p>The consequence in practice is a development-only one, documented in {@code
   * docs/native-mode.md}: a PS* realm key against LocalStack produces tokens whose signatures a
   * strict JOSE verifier rejects. Against real AWS the salt length is the one relying parties
   * expect.
   */
  @ParameterizedTest
  @DisplayName("PSS signatures verify, and the salt length is pinned")
  @CsvSource({
    "RSASSA_PSS_SHA_256, SHA-256, 32",
    "RSASSA_PSS_SHA_384, SHA-384, 48",
    "RSASSA_PSS_SHA_512, SHA-512, 64"
  })
  void rsaPssSignVerify(String kmsAlgorithm, String hash, int awsSaltLength) throws Exception {
    KmsSigningAlgorithm algorithm = KmsSigningAlgorithm.valueOf(kmsAlgorithm);
    byte[] message = "a token".getBytes(StandardCharsets.UTF_8);
    byte[] digest = MessageDigest.getInstance(hash).digest(message);

    byte[] signature = kms.sign(rsaKey, algorithm, digest);
    PublicKey publicKey = kms.publicKey(rsaKey);

    // emLen - hLen - 2, for a 2048-bit key: the largest salt PSS permits.
    int maximumSaltLength = 256 - awsSaltLength - 2;

    boolean documentedAws = pssVerifies(publicKey, hash, awsSaltLength, message, signature);
    boolean emulatorMaximum = pssVerifies(publicKey, hash, maximumSaltLength, message, signature);

    assertTrue(
        documentedAws || emulatorMaximum,
        kmsAlgorithm
            + " produced a signature that verifies at neither the documented AWS salt length ("
            + awsSaltLength
            + ") nor the maximum ("
            + maximumSaltLength
            + ") — the digest or the algorithm is wrong");
    assertFalse(documentedAws && emulatorMaximum, "a signature cannot verify at two salt lengths");
    System.out.printf(
        "  %s verified with salt length %d (%s)%n",
        kmsAlgorithm,
        documentedAws ? awsSaltLength : maximumSaltLength,
        documentedAws ? "documented AWS behaviour" : "LocalStack maximum-salt divergence");
  }

  private static boolean pssVerifies(
      PublicKey publicKey, String hash, int saltLength, byte[] message, byte[] signature) {
    try {
      Signature verifier = Signature.getInstance("RSASSA-PSS");
      verifier.setParameter(
          new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), saltLength, 1));
      verifier.initVerify(publicKey);
      verifier.update(message);
      return verifier.verify(signature);
    } catch (java.security.GeneralSecurityException e) {
      return false;
    }
  }

  @Test
  @DisplayName("the public key is fetched once and cached — it cannot change")
  void publicKeyIsCached() {
    PublicKey first = kms.publicKey(ecKey);
    PublicKey second = kms.publicKey(ecKey);
    assertSame(first, second);
  }

  @Test
  @DisplayName("signing with a symmetric key is refused by AWS, and reported as terminal")
  void cannotSignWithSymmetricKey() {
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> kms.sign(symmetricKey, KmsSigningAlgorithm.ECDSA_SHA_256, new byte[32]));
    assertFalse(e.isRetryable());
  }

  @Test
  @DisplayName("a native signing key with no explicit id is refused before any call is made")
  void nativeNeedsAnExplicitKey() {
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> kms.sign(null, KmsSigningAlgorithm.ECDSA_SHA_256, new byte[32]));
    assertTrue(e.getMessage().contains("no default"), e.getMessage());
  }

  // ------------------------------------------------------------------ defaults

  @Test
  @DisplayName("a provider with a default key uses it when none is named")
  void defaultKeyIsUsed() {
    AwsKmsProvider withDefault = new AwsKmsProvider(api, symmetricKey);
    EncryptionContext ctx = context("r", "k", "AES");
    byte[] material = "x".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(
        material, withDefault.decrypt(null, withDefault.encrypt(null, material, ctx), ctx));
    assertEquals(symmetricKey, withDefault.defaultKeyId());
    assertNotNull(withDefault.describe(null));
  }

  @Test
  @DisplayName("no key and no default names both settings that could fix it")
  void noKeyAtAll() {
    KmsException e =
        assertThrows(
            KmsException.class, () -> kms.encrypt(null, new byte[1], context("r", "k", "AES")));
    assertTrue(e.getMessage().contains("--spi-kms--aws--key-id"), e.getMessage());
    assertTrue(e.getMessage().contains("kmsKeyId"), e.getMessage());
  }
}
