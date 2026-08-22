package io.phasetwo.keycloak.kms.spi;

/**
 * What a KMS says about one of its keys.
 *
 * @param keyId the canonical identifier (an ARN for AWS), never the alias that was asked for —
 *     resolving the alias once at startup means later log lines name the key that is actually in
 *     use, which matters when an alias gets repointed
 * @param keySpec e.g. {@code SYMMETRIC_DEFAULT}, {@code ECC_NIST_P256}, {@code RSA_2048}
 * @param keyUsage {@code ENCRYPT_DECRYPT} or {@code SIGN_VERIFY}
 * @param enabled whether the key can currently be used
 */
public record KmsKeyDescription(String keyId, String keySpec, String keyUsage, boolean enabled) {

  public static final String USAGE_ENCRYPT_DECRYPT = "ENCRYPT_DECRYPT";
  public static final String USAGE_SIGN_VERIFY = "SIGN_VERIFY";

  public boolean isSymmetric() {
    return USAGE_ENCRYPT_DECRYPT.equals(keyUsage);
  }

  public boolean isSigning() {
    return USAGE_SIGN_VERIFY.equals(keyUsage);
  }

  public boolean isEc() {
    return keySpec != null && keySpec.startsWith("ECC_");
  }

  @Override
  public String toString() {
    return keyId
        + " ("
        + keySpec
        + ", "
        + keyUsage
        + ", "
        + (enabled ? "enabled" : "DISABLED")
        + ")";
  }
}
