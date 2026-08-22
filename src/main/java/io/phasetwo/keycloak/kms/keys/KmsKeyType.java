package io.phasetwo.keycloak.kms.keys;

import org.keycloak.crypto.KeyUse;

/**
 * The kinds of realm key this extension can hold, and the stock providers each one replaces.
 *
 * <p>The {@code contextValue} is what goes into the {@link
 * io.phasetwo.keycloak.kms.spi.EncryptionContext}, which is why it is defined here rather than
 * derived from a class name: it is part of the on-disk contract, and renaming a Java type must not
 * silently make every existing ciphertext undecryptable.
 */
public enum KmsKeyType {
  RSA("RSA", KeyUse.SIG, "rsa-generated", "rsa"),
  RSA_ENC("RSA_ENC", KeyUse.ENC, "rsa-enc-generated", "rsa-enc"),
  EC("EC", KeyUse.SIG, "ecdsa-generated"),
  HMAC("HMAC", KeyUse.SIG, "hmac-generated"),
  AES("AES", KeyUse.ENC, "aes-generated");

  private final String contextValue;
  private final KeyUse use;
  private final String[] stockProviderIds;

  KmsKeyType(String contextValue, KeyUse use, String... stockProviderIds) {
    this.contextValue = contextValue;
    this.use = use;
    this.stockProviderIds = stockProviderIds;
  }

  /** The value bound into the encryption context. Part of the on-disk contract. */
  public String contextValue() {
    return contextValue;
  }

  public KeyUse use() {
    return use;
  }

  /** Stock Keycloak provider ids that the migrator reads and this type replaces. */
  public String[] stockProviderIds() {
    return stockProviderIds.clone();
  }

  /** Which type, if any, replaces a given stock provider. Null when we do not handle it. */
  public static KmsKeyType forStockProvider(String providerId) {
    for (KmsKeyType t : values()) {
      for (String id : t.stockProviderIds) {
        if (id.equals(providerId)) {
          return t;
        }
      }
    }
    return null;
  }

  /** Whether this type's material is a secret key rather than a keypair. */
  public boolean isSecret() {
    return this == HMAC || this == AES;
  }
}
