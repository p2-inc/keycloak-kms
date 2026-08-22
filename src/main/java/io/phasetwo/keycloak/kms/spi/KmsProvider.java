package io.phasetwo.keycloak.kms.spi;

import java.security.PublicKey;
import org.keycloak.provider.Provider;

/**
 * A cloud key-management service, as this extension needs it.
 *
 * <p>Derived from {@code io.phasetwo.serverless.provider.keys.KmsClient}, which had exactly two
 * methods — {@code wrap} and {@code unwrap}. Three things were added on the way out of that
 * project: a key id (so one realm can use its own CMK), an {@link EncryptionContext} (so a
 * ciphertext is bound to the realm that owns it), and the signing half that makes non-extractable
 * keys possible.
 *
 * <p>Implementations must be thread-safe. They are shared across every realm on the instance and
 * called from request threads.
 */
public interface KmsProvider extends Provider {

  // ---------------------------------------------------------------- envelope mode (Tier A)

  /**
   * Encrypt key material under a symmetric KMS key.
   *
   * @param keyId the KMS key to use, or {@code null} for the configured default
   * @param plaintext the material; callers should keep this short-lived
   * @param context bound to the ciphertext and required again to decrypt
   */
  byte[] encrypt(String keyId, byte[] plaintext, EncryptionContext context);

  /**
   * Decrypt what {@link #encrypt} produced.
   *
   * @throws KmsException if the context does not match, the key is wrong, or access is denied — all
   *     of which are terminal, not retryable
   */
  byte[] decrypt(String keyId, byte[] ciphertext, EncryptionContext context);

  // ---------------------------------------------------------------- native mode (Tier B)

  /** Whether this backend can sign with non-extractable keys. */
  default boolean supportsNativeKeys() {
    return false;
  }

  /**
   * Sign a <em>digest</em> with a non-extractable key.
   *
   * @param keyId the asymmetric KMS key; never null for this operation
   * @param algorithm determines both the digest that was computed and the signature scheme
   * @param digest the already-computed message digest, {@code algorithm.digestAlgorithm()} long
   * @return a DER-encoded signature (ECDSA: SEQUENCE of r,s — callers wanting JOSE must convert)
   */
  default byte[] sign(String keyId, KmsSigningAlgorithm algorithm, byte[] digest) {
    throw new UnsupportedOperationException(
        getClass().getSimpleName() + " does not support non-extractable signing keys");
  }

  /** The public half of a non-extractable key, for JWKS and for deriving its kid. */
  default PublicKey publicKey(String keyId) {
    throw new UnsupportedOperationException(
        getClass().getSimpleName() + " does not support non-extractable signing keys");
  }

  // ---------------------------------------------------------------- both

  /**
   * Look up a key's spec, usage and state.
   *
   * <p>Called once at startup against the default key so that a missing key, a disabled key or a
   * missing IAM permission stops the server rather than surfacing at the first login.
   */
  KmsKeyDescription describe(String keyId);

  /** The default key id this provider was configured with, or null if none. */
  String defaultKeyId();

  @Override
  default void close() {}
}
