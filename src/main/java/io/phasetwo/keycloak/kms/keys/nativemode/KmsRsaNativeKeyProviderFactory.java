package io.phasetwo.keycloak.kms.keys.nativemode;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * {@code kms-rsa-native} — RS/PS signed inside the KMS. <strong>Experimental.</strong>
 *
 * <p>For realms whose clients cannot do ES256. Same machinery as {@link
 * KmsEcNativeKeyProviderFactory}, plus a certificate (stock RSA providers always have one, and SAML
 * descriptors read it) and the PSS algorithms.
 */
@AutoService(KeyProviderFactory.class)
public class KmsRsaNativeKeyProviderFactory extends AbstractKmsNativeKeyProviderFactory {

  public static final String ID = "kms-rsa-native";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  protected String keyType() {
    return KeyType.RSA;
  }

  @Override
  protected String defaultAlgorithm() {
    return Algorithm.RS256;
  }

  @Override
  protected String keySpecPrefix() {
    return "RSA_";
  }

  @Override
  protected String exampleKeySpec() {
    return "RSA_2048";
  }

  @Override
  protected KmsSigningAlgorithm signingAlgorithm(String joseAlgorithm) {
    KmsSigningAlgorithm algorithm = KmsSigningAlgorithm.fromJose(joseAlgorithm);
    if (algorithm == null || algorithm.isEc()) {
      throw new IllegalArgumentException(joseAlgorithm + " is not an RSA signing algorithm");
    }
    return algorithm;
  }

  @Override
  protected ProviderConfigProperty algorithmProperty() {
    ProviderConfigProperty property =
        new ProviderConfigProperty(
            org.keycloak.keys.Attributes.ALGORITHM_KEY,
            "Algorithm",
            "RS* uses PKCS#1 v1.5; PS* uses PSS. AWS KMS fixes the PSS salt length to the digest"
                + " length, which is what relying parties expect.",
            ProviderConfigProperty.LIST_TYPE,
            Algorithm.RS256);
    property.setOptions(
        java.util.List.of(
            Algorithm.RS256,
            Algorithm.RS384,
            Algorithm.RS512,
            Algorithm.PS256,
            Algorithm.PS384,
            Algorithm.PS512));
    return property;
  }

  @Override
  public String getHelpText() {
    return "EXPERIMENTAL. An RSA signing key held inside a cloud KMS. The private key is never"
        + " extractable and every token costs one KMS Sign call. Bring your own asymmetric CMK.";
  }
}
