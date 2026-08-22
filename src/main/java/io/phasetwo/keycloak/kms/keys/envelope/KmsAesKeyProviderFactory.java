package io.phasetwo.keycloak.kms.keys.envelope;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import org.keycloak.crypto.Algorithm;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * {@code kms-aes-generated} — the KMS-backed replacement for {@code aes-generated}.
 *
 * <p>Same shape as the HMAC factory, with AES's smaller default secret and no algorithm choice:
 * Keycloak's AES realm key has exactly one algorithm.
 */
@AutoService(KeyProviderFactory.class)
public class KmsAesKeyProviderFactory extends KmsHmacKeyProviderFactory {

  public static final String ID = "kms-aes-generated";

  /** Bytes. AES-128, matching stock's default. */
  public static final int DEFAULT_AES_SIZE = 16;

  @Override
  public String getId() {
    return ID;
  }

  @Override
  protected KmsKeyType keyType() {
    return KmsKeyType.AES;
  }

  @Override
  protected String defaultAlgorithm() {
    return Algorithm.AES;
  }

  @Override
  protected int defaultSecretSize() {
    return DEFAULT_AES_SIZE;
  }

  @Override
  protected ProviderConfigProperty algorithmProperty() {
    return null;
  }

  @Override
  public String getHelpText() {
    return "AES keys generated in memory and stored encrypted under a cloud KMS key. Used to"
        + " encrypt client secrets and cookie payloads.";
  }
}
