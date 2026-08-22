package io.phasetwo.keycloak.kms.aws;

import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** AWS KMS behind the {@code kms} SPI. */
public class AwsKmsProvider implements KmsProvider {

  private final KmsApi api;
  private final String defaultKeyId;

  /**
   * Public keys and key descriptions, cached for the life of the process.
   *
   * <p>Safe to cache indefinitely: a CMK's public half and its spec never change. Its
   * <em>enabled</em> flag can, but that is checked at startup and enforced by KMS on every
   * operation anyway — caching it would not let a disabled key keep signing.
   */
  private final Map<String, PublicKey> publicKeys = new ConcurrentHashMap<>();

  private final Map<String, KmsKeyDescription> descriptions = new ConcurrentHashMap<>();

  public AwsKmsProvider(KmsApi api, String defaultKeyId) {
    this.api = api;
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

  @Override
  public byte[] encrypt(String keyId, byte[] plaintext, EncryptionContext context) {
    return api.encrypt(requireKey(keyId), plaintext, context);
  }

  @Override
  public byte[] decrypt(String keyId, byte[] ciphertext, EncryptionContext context) {
    return api.decrypt(requireKey(keyId), ciphertext, context);
  }

  @Override
  public byte[] sign(String keyId, KmsSigningAlgorithm algorithm, byte[] digest) {
    if (keyId == null || keyId.isBlank()) {
      throw new KmsException("a native signing key must be named explicitly; there is no default");
    }
    return api.sign(keyId, algorithm, digest);
  }

  @Override
  public PublicKey publicKey(String keyId) {
    return publicKeys.computeIfAbsent(keyId, id -> parsePublicKey(api.getPublicKey(id), id));
  }

  @Override
  public KmsKeyDescription describe(String keyId) {
    return descriptions.computeIfAbsent(requireKey(keyId), api::describeKey);
  }

  private String requireKey(String keyId) {
    if (keyId != null && !keyId.isBlank()) {
      return keyId;
    }
    if (defaultKeyId == null || defaultKeyId.isBlank()) {
      throw new KmsException(
          "no KMS key id given and no default configured — set --spi-kms--aws--key-id, or give the"
              + " key provider component its own kmsKeyId");
    }
    return defaultKeyId;
  }

  /**
   * Turn a DER SubjectPublicKeyInfo into a {@link PublicKey}.
   *
   * <p>The encoding names its own algorithm, but {@link KeyFactory} has to be told which one, so
   * this tries the two that KMS can produce. Reading the OID out of the DER by hand would be exact
   * — and would be a hand-rolled ASN.1 parser to save one failed {@code generatePublic}.
   */
  private static PublicKey parsePublicKey(byte[] der, String keyId) {
    X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
    for (String algorithm : new String[] {"EC", "RSA"}) {
      try {
        return KeyFactory.getInstance(algorithm).generatePublic(spec);
      } catch (GeneralSecurityException ignored) {
        // Try the other one.
      }
    }
    throw new KmsException(
        "could not read the public key of "
            + keyId
            + " as either EC or RSA — is it a signing key?");
  }
}
