package io.phasetwo.keycloak.kms.local;

import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A KMS that is not a KMS: AES-256-GCM under a locally held KEK, plus deterministically derived
 * keypairs for the native-mode surface.
 *
 * <p>It exists for two reasons — unit tests that must not need AWS, and a {@code docker compose}
 * dev environment that starts with one command. It provides no protection whatsoever against anyone
 * who can read the Keycloak configuration, and says so at every startup.
 *
 * <p>It does enforce the {@link EncryptionContext}, as GCM additional authenticated data. That is
 * deliberate: if the local backend ignored the context, every test written against it would pass
 * while the isolation property it is supposed to prove went untested.
 *
 * <p><strong>Key ids</strong> encode the key spec, so tests and dev realms can ask for whatever
 * they need without provisioning anything:
 *
 * <ul>
 *   <li>{@code ec256:<name>}, {@code ec384:<name>}, {@code ec521:<name>} — signing, EC
 *   <li>{@code rsa2048:<name>}, {@code rsa3072:<name>}, {@code rsa4096:<name>} — signing, RSA
 *   <li>anything else — symmetric, for envelope mode
 * </ul>
 */
public class LocalKmsProvider implements KmsProvider {

  private static final int IV_BYTES = 12;
  private static final int TAG_BITS = 128;

  /** PKCS#1 v1.5 DigestInfo prefixes, so a digest signature matches what a real KMS produces. */
  private static final Map<String, byte[]> DIGEST_INFO_PREFIX =
      Map.of(
          "SHA-256", HexFormat.of().parseHex("3031300d060960864801650304020105000420"),
          "SHA-384", HexFormat.of().parseHex("3041300d060960864801650304020205000430"),
          "SHA-512", HexFormat.of().parseHex("3051300d060960864801650304020305000440"));

  private final SecretKeySpec kek;
  private final String defaultKeyId;
  private final SecureRandom random = new SecureRandom();
  private final Map<String, KeyPair> derivedKeys = new ConcurrentHashMap<>();

  public LocalKmsProvider(byte[] kekBytes, String defaultKeyId) {
    if (kekBytes.length != 16 && kekBytes.length != 24 && kekBytes.length != 32) {
      throw new IllegalArgumentException("KEK must be 16/24/32 bytes, got " + kekBytes.length);
    }
    this.kek = new SecretKeySpec(kekBytes, "AES");
    this.defaultKeyId = defaultKeyId;
  }

  @Override
  public String defaultKeyId() {
    return defaultKeyId;
  }

  @Override
  public boolean supportsNativeKeys() {
    return true;
  }

  // ------------------------------------------------------------------ envelope

  @Override
  public byte[] encrypt(String keyId, byte[] plaintext, EncryptionContext context) {
    try {
      byte[] iv = new byte[IV_BYTES];
      random.nextBytes(iv);
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.ENCRYPT_MODE, kek, new GCMParameterSpec(TAG_BITS, iv));
      c.updateAAD(aad(keyId, context));
      byte[] ct = c.doFinal(plaintext);
      byte[] out = new byte[IV_BYTES + ct.length];
      System.arraycopy(iv, 0, out, 0, IV_BYTES);
      System.arraycopy(ct, 0, out, IV_BYTES, ct.length);
      return out;
    } catch (GeneralSecurityException e) {
      throw new KmsException("local encrypt failed", e);
    }
  }

  @Override
  public byte[] decrypt(String keyId, byte[] ciphertext, EncryptionContext context) {
    if (ciphertext.length <= IV_BYTES) {
      throw new KmsException("local decrypt failed: ciphertext too short");
    }
    try {
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.DECRYPT_MODE, kek, new GCMParameterSpec(TAG_BITS, ciphertext, 0, IV_BYTES));
      c.updateAAD(aad(keyId, context));
      return c.doFinal(ciphertext, IV_BYTES, ciphertext.length - IV_BYTES);
    } catch (GeneralSecurityException e) {
      throw new KmsException(
          "local decrypt failed — wrong KEK, corrupt value, or an encryption context that does not"
              + " match the one it was sealed with ("
              + context
              + ")",
          e);
    }
  }

  /**
   * The GCM AAD. Includes the key id as well as the context, because with a single KEK the key id
   * is otherwise not bound to anything — and a per-realm CMK is a documented feature, so tests that
   * exercise it must see the same isolation a real KMS would give them.
   */
  private byte[] aad(String keyId, EncryptionContext context) {
    StringBuilder sb = new StringBuilder();
    sb.append("keyId=").append(keyId == null ? defaultKeyId : keyId);
    if (context != null) {
      context.asMap().entrySet().stream()
          .sorted(Map.Entry.comparingByKey())
          .forEach(e -> sb.append('\n').append(e.getKey()).append('=').append(e.getValue()));
    }
    return sb.toString().getBytes(StandardCharsets.UTF_8);
  }

  // ------------------------------------------------------------------ native

  @Override
  public byte[] sign(String keyId, KmsSigningAlgorithm algorithm, byte[] digest) {
    KeyPair kp = keyPair(keyId);
    try {
      if (algorithm.isEc()) {
        // NONEwithECDSA signs the supplied bytes AS the digest — the JCA equivalent of
        // KMS MessageType=DIGEST — and returns DER, which is what KMS returns too.
        Signature s = Signature.getInstance("NONEwithECDSA");
        s.initSign(kp.getPrivate());
        s.update(digest);
        return s.sign();
      }
      if (algorithm.name().startsWith("RSASSA_PKCS1")) {
        byte[] prefix = DIGEST_INFO_PREFIX.get(algorithm.digestAlgorithm());
        byte[] digestInfo = new byte[prefix.length + digest.length];
        System.arraycopy(prefix, 0, digestInfo, 0, prefix.length);
        System.arraycopy(digest, 0, digestInfo, prefix.length, digest.length);
        Signature s = Signature.getInstance("NONEwithRSA");
        s.initSign(kp.getPrivate());
        s.update(digestInfo);
        return s.sign();
      }
      throw new KmsException(
          "the local KMS backend does not implement "
              + algorithm
              + " — PSS over a pre-computed digest has no JCA equivalent. Use the aws backend (or"
              + " LocalStack) to exercise PSS.");
    } catch (GeneralSecurityException e) {
      throw new KmsException("local sign failed for " + algorithm, e);
    }
  }

  @Override
  public PublicKey publicKey(String keyId) {
    return keyPair(keyId).getPublic();
  }

  /**
   * Derive a keypair deterministically from (KEK, keyId), so a restart reproduces it.
   *
   * <p>Deterministic derivation via a seeded {@code SHA1PRNG} is not a defensible way to make real
   * keys — it is here so that a dev realm survives {@code docker compose restart} without a
   * database of its own, and it is unreachable unless an operator has explicitly selected the
   * {@code local} backend.
   */
  private KeyPair keyPair(String keyId) {
    if (keyId == null) {
      throw new KmsException("a native key operation needs an explicit key id");
    }
    return derivedKeys.computeIfAbsent(
        keyId,
        id -> {
          try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(kek.getEncoded());
            md.update(id.getBytes(StandardCharsets.UTF_8));
            SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
            prng.setSeed(md.digest());

            String spec = keySpecOf(id);
            if (spec.startsWith("ECC_")) {
              KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
              g.initialize(new ECGenParameterSpec(curveOf(spec)), prng);
              return g.generateKeyPair();
            }
            if (spec.startsWith("RSA_")) {
              KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
              g.initialize(Integer.parseInt(spec.substring("RSA_".length())), prng);
              return g.generateKeyPair();
            }
            throw new KmsException(
                "key id '"
                    + id
                    + "' is symmetric; native signing needs an id prefixed ec256:/ec384:/ec521:/"
                    + "rsa2048:/rsa3072:/rsa4096:");
          } catch (GeneralSecurityException e) {
            throw new KmsException("local key derivation failed for " + id, e);
          }
        });
  }

  // ------------------------------------------------------------------ metadata

  @Override
  public KmsKeyDescription describe(String keyId) {
    String id = keyId == null ? defaultKeyId : keyId;
    if (id == null) {
      throw new KmsException("no key id given and no default configured");
    }
    String spec = keySpecOf(id);
    boolean signing = !"SYMMETRIC_DEFAULT".equals(spec);
    return new KmsKeyDescription(
        id,
        spec,
        signing ? KmsKeyDescription.USAGE_SIGN_VERIFY : KmsKeyDescription.USAGE_ENCRYPT_DECRYPT,
        true);
  }

  static String keySpecOf(String keyId) {
    int colon = keyId.indexOf(':');
    String prefix = colon < 0 ? "" : keyId.substring(0, colon);
    return switch (prefix) {
      case "ec256" -> "ECC_NIST_P256";
      case "ec384" -> "ECC_NIST_P384";
      case "ec521" -> "ECC_NIST_P521";
      case "rsa2048" -> "RSA_2048";
      case "rsa3072" -> "RSA_3072";
      case "rsa4096" -> "RSA_4096";
      default -> "SYMMETRIC_DEFAULT";
    };
  }

  private static String curveOf(String spec) {
    return switch (spec) {
      case "ECC_NIST_P256" -> "secp256r1";
      case "ECC_NIST_P384" -> "secp384r1";
      case "ECC_NIST_P521" -> "secp521r1";
      default -> throw new KmsException("not an EC key spec: " + spec);
    };
  }
}
