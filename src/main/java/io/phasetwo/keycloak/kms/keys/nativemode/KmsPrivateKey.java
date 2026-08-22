package io.phasetwo.keycloak.kms.keys.nativemode;

import io.phasetwo.keycloak.kms.spi.KmsProvider;
import java.security.PrivateKey;

/**
 * A private key that has no bytes.
 *
 * <p>This is the object Keycloak hands to {@code Signature.initSign()}. It carries nothing but a
 * KMS key id and a way to reach the KMS; {@link #getEncoded()} returns null because there is
 * genuinely nothing to encode — the material is inside AWS and cannot be extracted by anyone,
 * including us.
 *
 * <p>Returning null from {@code getFormat()} and {@code getEncoded()} is what makes the JCA
 * dispatch work. SunEC and SunRsaSign both declare {@code SupportedKeyClasses}, so the JDK's
 * delayed provider selection skips them for a key that implements neither {@code ECPrivateKey} nor
 * {@code RSAPrivateKey}, and reaches {@link KmsJcaProvider} instead. An opaque key is the
 * mechanism, not an accident of it.
 */
public final class KmsPrivateKey implements PrivateKey {

  private final transient KmsProvider kms;
  private final String keyId;
  private final String algorithm;

  /**
   * @param kms the backend that will perform the signature
   * @param keyId the asymmetric CMK
   * @param algorithm {@code EC} or {@code RSA} — what {@code Signature} will ask for
   */
  public KmsPrivateKey(KmsProvider kms, String keyId, String algorithm) {
    this.kms = kms;
    this.keyId = keyId;
    this.algorithm = algorithm;
  }

  public KmsProvider kms() {
    return kms;
  }

  public String keyId() {
    return keyId;
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }

  /** Null: there is no encoding of a key that never leaves the HSM. */
  @Override
  public String getFormat() {
    return null;
  }

  /** Null, for the same reason. */
  @Override
  public byte[] getEncoded() {
    return null;
  }

  @Override
  public String toString() {
    return "KmsPrivateKey[" + algorithm + ", " + keyId + "]";
  }
}
