package io.phasetwo.keycloak.kms.keys;

import org.keycloak.provider.ProviderConfigProperty;

/**
 * Component-config keys this extension adds, alongside Keycloak's own {@code
 * org.keycloak.keys.Attributes}.
 *
 * <p>{@link #WRAPPED_MATERIAL} is named to match the {@code wrappedMaterial} convention that secret
 * scanners in this ecosystem key on, so a scanner enforces that its value is a {@code kms://}
 * reference rather than plaintext. Its value is never key material; the plaintext exists only in
 * memory.
 */
public final class KmsAttributes {

  /** {@code kms://v1/<base64url>} — the KMS ciphertext of this key's private material. */
  public static final String WRAPPED_MATERIAL = "wrappedMaterial";

  /** Optional per-provider KMS key. Required for native mode, optional for envelope mode. */
  public static final String KMS_KEY_ID = "kmsKeyId";

  /** X.509 SubjectPublicKeyInfo, base64. Public material, stored in the clear. */
  public static final String PUBLIC_KEY = "publicKey";

  /** Set by the migrator: the component id this key was migrated from. Provenance, not config. */
  public static final String MIGRATED_FROM = "migratedFromComponentId";

  /** Set by the migrator: the stock provider id this key came from. */
  public static final String MIGRATED_FROM_PROVIDER = "migratedFromProvider";

  public static final ProviderConfigProperty KMS_KEY_ID_PROPERTY =
      new ProviderConfigProperty(
          KMS_KEY_ID,
          "KMS key",
          "The KMS key protecting this provider's material. Leave blank to use the server-wide"
              + " default (--spi-kms--aws--key-id).",
          ProviderConfigProperty.STRING_TYPE,
          null);

  private KmsAttributes() {}
}
