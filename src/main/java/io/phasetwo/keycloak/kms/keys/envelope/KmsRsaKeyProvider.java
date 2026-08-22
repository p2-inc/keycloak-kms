package io.phasetwo.keycloak.kms.keys.envelope;

import io.phasetwo.keycloak.kms.keys.AbstractKmsKeyProvider;
import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import io.phasetwo.keycloak.kms.spi.KmsException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.models.KeycloakSession;

/**
 * An RSA realm key whose private half lives in the database only as KMS ciphertext.
 *
 * <p>The certificate stays in config in the clear, exactly as stock stores it — it is public
 * material, and keeping it there means the public key needs no KMS call to derive.
 */
public class KmsRsaKeyProvider extends AbstractKmsKeyProvider {

  private final String defaultAlgorithm;

  public KmsRsaKeyProvider(
      KeycloakSession session, ComponentModel model, KmsKeyType keyType, String defaultAlgorithm) {
    super(session, model, keyType);
    this.defaultAlgorithm = defaultAlgorithm;
  }

  @Override
  protected KeyWrapper buildKey(byte[] material, KeyStatus status) {
    try {
      PrivateKey privateKey =
          KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(material));
      X509Certificate certificate =
          PemUtils.decodeCertificate(model.get(Attributes.CERTIFICATE_KEY));
      if (certificate == null) {
        throw new KmsException(
            "key provider " + model.getId() + " has wrapped material but no certificate");
      }

      KeyWrapper key = baseKey(status);
      key.setType(KeyType.RSA);
      key.setAlgorithm(algorithm(defaultAlgorithm));
      key.setPrivateKey(privateKey);
      key.setPublicKey(certificate.getPublicKey());
      key.setCertificate(certificate);
      return key;
    } catch (GeneralSecurityException e) {
      throw new KmsException(
          "the material unwrapped for " + model.getId() + " is not an RSA private key", e);
    } finally {
      // The PKCS#8 bytes are done with; the PrivateKey object holds what is still needed.
      java.util.Arrays.fill(material, (byte) 0);
    }
  }
}
