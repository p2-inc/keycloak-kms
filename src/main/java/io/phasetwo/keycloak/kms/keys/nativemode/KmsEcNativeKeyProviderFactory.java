package io.phasetwo.keycloak.kms.keys.nativemode;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * {@code kms-ec-native} — ES256/384/512 signed inside the KMS. <strong>Experimental.</strong>
 *
 * <p>The reference native provider, and the one to reach for first. An ECDSA signature inside KMS
 * is faster and cheaper per operation than an RSA one, ES256 is understood by every relying party
 * that matters, and EC sidesteps the PSS parameter negotiation that RSA needs.
 */
@AutoService(KeyProviderFactory.class)
public class KmsEcNativeKeyProviderFactory extends AbstractKmsNativeKeyProviderFactory {

  public static final String ID = "kms-ec-native";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  protected String keyType() {
    return KeyType.EC;
  }

  @Override
  protected String defaultAlgorithm() {
    return Algorithm.ES256;
  }

  @Override
  protected String keySpecPrefix() {
    return "ECC_";
  }

  @Override
  protected String exampleKeySpec() {
    return "ECC_NIST_P256";
  }

  /**
   * Stock ECDSA providers make the certificate optional ({@code ecGenerateCertificate}), and an EC
   * realm key is not normally used for SAML, so minting one by default would spend a KMS call and
   * add a config value nobody reads.
   */
  @Override
  protected boolean certificateByDefault() {
    return false;
  }

  @Override
  protected KmsSigningAlgorithm signingAlgorithm(String joseAlgorithm) {
    KmsSigningAlgorithm algorithm = KmsSigningAlgorithm.fromJose(joseAlgorithm);
    if (algorithm == null || !algorithm.isEc()) {
      throw new IllegalArgumentException(joseAlgorithm + " is not an EC signing algorithm");
    }
    return algorithm;
  }

  @Override
  protected ProviderConfigProperty algorithmProperty() {
    ProviderConfigProperty property =
        new ProviderConfigProperty(
            org.keycloak.keys.Attributes.ALGORITHM_KEY,
            "Algorithm",
            "Must match the KMS key's curve: ES256 for ECC_NIST_P256, ES384 for P384, ES512 for"
                + " P521.",
            ProviderConfigProperty.LIST_TYPE,
            Algorithm.ES256);
    property.setOptions(java.util.List.of(Algorithm.ES256, Algorithm.ES384, Algorithm.ES512));
    return property;
  }

  @Override
  public String getHelpText() {
    return "EXPERIMENTAL. An EC signing key held inside a cloud KMS. The private key is never"
        + " extractable and every token costs one KMS Sign call. Bring your own asymmetric CMK.";
  }
}
