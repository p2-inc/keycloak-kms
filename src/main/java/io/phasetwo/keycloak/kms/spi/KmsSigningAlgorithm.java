package io.phasetwo.keycloak.kms.spi;

import org.keycloak.crypto.Algorithm;

/**
 * The signing algorithms a KMS can be asked for, named as AWS KMS names them.
 *
 * <p>Every one of these is a <em>digest</em> signature: the caller hashes the message locally and
 * sends the digest. That is not only an optimisation to stay under the KMS 4 KB message limit — it
 * keeps the hash computation in our control, which matters because {@code SignatureSpi} hands us a
 * stream of {@code update()} calls and expects us to have hashed it by the time {@code sign()} is
 * called.
 */
public enum KmsSigningAlgorithm {
  ECDSA_SHA_256("SHA-256", Algorithm.ES256),
  ECDSA_SHA_384("SHA-384", Algorithm.ES384),
  ECDSA_SHA_512("SHA-512", Algorithm.ES512),
  RSASSA_PKCS1_V1_5_SHA_256("SHA-256", Algorithm.RS256),
  RSASSA_PKCS1_V1_5_SHA_384("SHA-384", Algorithm.RS384),
  RSASSA_PKCS1_V1_5_SHA_512("SHA-512", Algorithm.RS512),
  RSASSA_PSS_SHA_256("SHA-256", Algorithm.PS256),
  RSASSA_PSS_SHA_384("SHA-384", Algorithm.PS384),
  RSASSA_PSS_SHA_512("SHA-512", Algorithm.PS512);

  private final String digestAlgorithm;
  private final String joseAlgorithm;

  KmsSigningAlgorithm(String digestAlgorithm, String joseAlgorithm) {
    this.digestAlgorithm = digestAlgorithm;
    this.joseAlgorithm = joseAlgorithm;
  }

  /** JCA name of the digest to compute before calling {@link KmsProvider#sign}. */
  public String digestAlgorithm() {
    return digestAlgorithm;
  }

  /** The JOSE {@code alg} this produces, e.g. {@code ES256}. */
  public String joseAlgorithm() {
    return joseAlgorithm;
  }

  public boolean isEc() {
    return name().startsWith("ECDSA");
  }

  /** Resolve from a JOSE algorithm name. Returns null when the algorithm has no KMS equivalent. */
  public static KmsSigningAlgorithm fromJose(String jose) {
    for (KmsSigningAlgorithm a : values()) {
      if (a.joseAlgorithm.equals(jose)) {
        return a;
      }
    }
    return null;
  }
}
