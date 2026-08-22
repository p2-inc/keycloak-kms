package io.phasetwo.keycloak.kms.local;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class LocalKmsProviderTest {

  private static final byte[] KEK =
      "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
  private static final byte[] OTHER_KEK =
      "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.UTF_8);
  private static final byte[] MATERIAL =
      "a realm's private key, notionally".getBytes(StandardCharsets.UTF_8);

  private LocalKmsProvider kms() {
    return new LocalKmsProvider(KEK, "default");
  }

  private static EncryptionContext ctx(String realm, String kid) {
    return EncryptionContext.forKey(realm, kid, "RSA");
  }

  @Test
  @DisplayName("encrypt/decrypt round-trips")
  void roundTrip() {
    LocalKmsProvider kms = kms();
    EncryptionContext c = ctx("realm-a", "kid-1");
    byte[] ct = kms.encrypt(null, MATERIAL, c);
    assertFalse(Arrays.equals(MATERIAL, ct), "ciphertext must not be the plaintext");
    assertArrayEquals(MATERIAL, kms.decrypt(null, ct, c));
  }

  @Test
  @DisplayName("encryption is non-deterministic (fresh IV per call)")
  void freshIvPerCall() {
    LocalKmsProvider kms = kms();
    EncryptionContext c = ctx("realm-a", "kid-1");
    assertFalse(Arrays.equals(kms.encrypt(null, MATERIAL, c), kms.encrypt(null, MATERIAL, c)));
  }

  // ---- the tenancy property: this is what serverless's envelope did NOT have ----

  @Test
  @DisplayName("a ciphertext sealed for realm A does not decrypt for realm B")
  void realmIsolation() {
    LocalKmsProvider kms = kms();
    byte[] ct = kms.encrypt(null, MATERIAL, ctx("realm-a", "kid-1"));
    KmsException e =
        assertThrows(KmsException.class, () -> kms.decrypt(null, ct, ctx("realm-b", "kid-1")));
    assertTrue(e.getMessage().contains("encryption context"), e.getMessage());
  }

  @Test
  @DisplayName("a ciphertext relabelled with a different kid does not decrypt")
  void kidIsolation() {
    LocalKmsProvider kms = kms();
    byte[] ct = kms.encrypt(null, MATERIAL, ctx("realm-a", "kid-1"));
    assertThrows(KmsException.class, () -> kms.decrypt(null, ct, ctx("realm-a", "kid-2")));
  }

  @Test
  @DisplayName("a ciphertext relabelled with a different key type does not decrypt")
  void keyTypeIsolation() {
    LocalKmsProvider kms = kms();
    byte[] ct = kms.encrypt(null, MATERIAL, EncryptionContext.forKey("r", "k", "RSA"));
    assertThrows(
        KmsException.class,
        () -> kms.decrypt(null, ct, EncryptionContext.forKey("r", "k", "HMAC")));
  }

  @Test
  @DisplayName("a ciphertext sealed under one CMK does not decrypt under another")
  void perKeyIsolation() {
    LocalKmsProvider kms = kms();
    EncryptionContext c = ctx("realm-a", "kid-1");
    byte[] ct = kms.encrypt("cmk-one", MATERIAL, c);
    assertThrows(KmsException.class, () -> kms.decrypt("cmk-two", ct, c));
  }

  @Test
  @DisplayName("a different KEK cannot read the ciphertext")
  void wrongKek() {
    EncryptionContext c = ctx("realm-a", "kid-1");
    byte[] ct = kms().encrypt(null, MATERIAL, c);
    LocalKmsProvider other = new LocalKmsProvider(OTHER_KEK, "default");
    assertThrows(KmsException.class, () -> other.decrypt(null, ct, c));
  }

  @Test
  @DisplayName(
      "two providers sharing a KEK read each other's ciphertext — the multi-instance property")
  void sharedKekIsInterchangeable() {
    EncryptionContext c = ctx("realm-a", "kid-1");
    byte[] ct = new LocalKmsProvider(KEK, "default").encrypt(null, MATERIAL, c);
    assertArrayEquals(MATERIAL, new LocalKmsProvider(KEK, "default").decrypt(null, ct, c));
  }

  @Test
  @DisplayName("a truncated or corrupt ciphertext fails cleanly rather than returning garbage")
  void corruptCiphertext() {
    LocalKmsProvider kms = kms();
    EncryptionContext c = ctx("realm-a", "kid-1");
    byte[] ct = kms.encrypt(null, MATERIAL, c);
    byte[] truncated = Arrays.copyOf(ct, ct.length - 1);
    assertThrows(KmsException.class, () -> kms.decrypt(null, truncated, c));

    byte[] flipped = ct.clone();
    flipped[flipped.length - 1] ^= 0x01;
    assertThrows(KmsException.class, () -> kms.decrypt(null, flipped, c));

    assertThrows(KmsException.class, () -> kms.decrypt(null, new byte[4], c));
  }

  @Test
  @DisplayName("a KEK of the wrong length is rejected at construction")
  void badKekLength() {
    assertThrows(IllegalArgumentException.class, () -> new LocalKmsProvider(new byte[31], "d"));
  }

  // ---- native surface ----

  @ParameterizedTest
  @DisplayName("an EC digest signature verifies against the full message with the JOSE algorithm")
  @CsvSource({
    "ec256:signing, ECDSA_SHA_256, SHA-256, SHA256withECDSA",
    "ec384:signing, ECDSA_SHA_384, SHA-384, SHA384withECDSA",
    "ec521:signing, ECDSA_SHA_512, SHA-512, SHA512withECDSA"
  })
  void ecDigestSignatureVerifies(String keyId, String alg, String digestAlg, String javaAlg)
      throws Exception {
    LocalKmsProvider kms = kms();
    byte[] message = "the token to be signed".getBytes(StandardCharsets.UTF_8);
    byte[] digest = MessageDigest.getInstance(digestAlg).digest(message);

    byte[] signature = kms.sign(keyId, KmsSigningAlgorithm.valueOf(alg), digest);
    PublicKey pub = kms.publicKey(keyId);

    // The contract: signing the digest must be indistinguishable from signing the message.
    // That is what makes MessageType=DIGEST safe to use on the token path.
    Signature v = Signature.getInstance(javaAlg);
    v.initVerify(pub);
    v.update(message);
    assertTrue(v.verify(signature), javaAlg + " signature over the digest did not verify");
  }

  @ParameterizedTest
  @DisplayName("an RSA PKCS#1 digest signature verifies against the full message")
  @CsvSource({
    "rsa2048:signing, RSASSA_PKCS1_V1_5_SHA_256, SHA-256, SHA256withRSA",
    "rsa2048:signing, RSASSA_PKCS1_V1_5_SHA_384, SHA-384, SHA384withRSA",
    "rsa2048:signing, RSASSA_PKCS1_V1_5_SHA_512, SHA-512, SHA512withRSA"
  })
  void rsaDigestSignatureVerifies(String keyId, String alg, String digestAlg, String javaAlg)
      throws Exception {
    LocalKmsProvider kms = kms();
    byte[] message = "the token to be signed".getBytes(StandardCharsets.UTF_8);
    byte[] digest = MessageDigest.getInstance(digestAlg).digest(message);

    byte[] signature = kms.sign(keyId, KmsSigningAlgorithm.valueOf(alg), digest);

    Signature v = Signature.getInstance(javaAlg);
    v.initVerify(kms.publicKey(keyId));
    v.update(message);
    assertTrue(v.verify(signature), javaAlg + " signature over the DigestInfo did not verify");
  }

  @Test
  @DisplayName("a derived keypair is stable across provider instances, so a restart keeps the kid")
  void derivationIsDeterministic() {
    PublicKey a = new LocalKmsProvider(KEK, "d").publicKey("ec256:stable");
    PublicKey b = new LocalKmsProvider(KEK, "d").publicKey("ec256:stable");
    assertArrayEquals(a.getEncoded(), b.getEncoded());
  }

  @Test
  @DisplayName("a different KEK derives a different keypair")
  void derivationIsKekBound() {
    PublicKey a = new LocalKmsProvider(KEK, "d").publicKey("ec256:stable");
    PublicKey b = new LocalKmsProvider(OTHER_KEK, "d").publicKey("ec256:stable");
    assertFalse(Arrays.equals(a.getEncoded(), b.getEncoded()));
  }

  @Test
  @DisplayName("different key ids derive different keypairs")
  void derivationIsKeyIdBound() {
    LocalKmsProvider kms = kms();
    assertFalse(
        Arrays.equals(
            kms.publicKey("ec256:a").getEncoded(), kms.publicKey("ec256:b").getEncoded()));
  }

  @Test
  @DisplayName("PSS is refused with an explanation rather than a wrong signature")
  void pssRefused() {
    LocalKmsProvider kms = kms();
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> kms.sign("rsa2048:x", KmsSigningAlgorithm.RSASSA_PSS_SHA_256, new byte[32]));
    assertTrue(e.getMessage().contains("aws"), e.getMessage());
  }

  @Test
  @DisplayName("a symmetric key id cannot be used for signing")
  void symmetricCannotSign() {
    LocalKmsProvider kms = kms();
    assertThrows(
        KmsException.class,
        () -> kms.sign("plain-symmetric", KmsSigningAlgorithm.ECDSA_SHA_256, new byte[32]));
  }

  @Test
  @DisplayName("describe reports spec and usage from the key id convention")
  void describe() {
    LocalKmsProvider kms = kms();
    KmsKeyDescription sym = kms.describe(null);
    assertEquals("SYMMETRIC_DEFAULT", sym.keySpec());
    assertTrue(sym.isSymmetric());
    assertTrue(sym.enabled());

    KmsKeyDescription ec = kms.describe("ec256:x");
    assertEquals("ECC_NIST_P256", ec.keySpec());
    assertTrue(ec.isSigning());
    assertTrue(ec.isEc());

    assertEquals("RSA_4096", kms.describe("rsa4096:x").keySpec());
  }

  @Test
  @DisplayName("the backend advertises native support")
  void supportsNative() {
    assertTrue(kms().supportsNativeKeys());
  }
}
