package io.phasetwo.keycloak.kms.keys.envelope;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import org.keycloak.crypto.Algorithm;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * {@code kms-rsa-enc-generated} — the KMS-backed replacement for {@code rsa-enc-generated}.
 *
 * <p>Identical machinery to {@link KmsRsaKeyProviderFactory}; only the key use and the default
 * algorithm differ. Keycloak keeps encryption keys separate from signing keys so that a key can be
 * rotated for one purpose without disturbing the other, and this mirrors that.
 */
@AutoService(KeyProviderFactory.class)
public class KmsRsaEncKeyProviderFactory extends KmsRsaKeyProviderFactory {

  public static final String ID = "kms-rsa-enc-generated";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  protected KmsKeyType keyType() {
    return KmsKeyType.RSA_ENC;
  }

  @Override
  protected String defaultAlgorithm() {
    return Algorithm.RSA_OAEP;
  }

  @Override
  protected ProviderConfigProperty algorithmProperty() {
    return Attributes.RS_ENC_ALGORITHM_PROPERTY;
  }

  @Override
  public String getHelpText() {
    return "RSA encryption keys generated in memory and stored encrypted under a cloud KMS key.";
  }
}
