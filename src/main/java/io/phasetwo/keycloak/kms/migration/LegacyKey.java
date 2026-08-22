package io.phasetwo.keycloak.kms.migration;

import io.phasetwo.keycloak.kms.keys.KmsKeyType;

/**
 * Plaintext key material read out of a stock Keycloak key provider, on its way into a KMS.
 *
 * <p>Short-lived by design: an instance of this holds the very thing the extension exists to get
 * out of the database, so it is created inside a migration and dropped as soon as the material has
 * been sealed.
 *
 * @param type what this becomes on the other side
 * @param targetProviderId the KMS provider id that will hold it
 * @param kid the key id to preserve — the whole point of the exercise
 * @param material PKCS#8 for a keypair, raw bytes for a secret
 * @param certificatePem the public certificate, carried across unchanged (null for secrets)
 * @param algorithm the JOSE algorithm the legacy provider declared, or null for its default
 * @param priority the legacy provider's priority, preserved so signing behaviour does not change
 * @param kidWasExplicit whether the kid was stored in config or derived from the public key
 */
public record LegacyKey(
    KmsKeyType type,
    String targetProviderId,
    String kid,
    byte[] material,
    String certificatePem,
    String algorithm,
    long priority,
    boolean kidWasExplicit) {

  /** Wipe the plaintext once it has been sealed. */
  public void destroy() {
    java.util.Arrays.fill(material, (byte) 0);
  }

  /** Deliberately omits the material. */
  @Override
  public String toString() {
    return "LegacyKey[" + type + ", kid=" + kid + ", " + material.length + " bytes]";
  }
}
