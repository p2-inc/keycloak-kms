package io.phasetwo.keycloak.kms.keys.envelope;

import io.phasetwo.keycloak.kms.keys.AbstractKmsKeyProvider;
import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import javax.crypto.spec.SecretKeySpec;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;

/**
 * HMAC and AES realm keys, stored as KMS ciphertext.
 *
 * <p>These matter more than they look. The HMAC key signs action tokens and the identity cookie;
 * the AES key encrypts client secrets and cookie payloads. An attacker with the HMAC secret can
 * forge a password-reset link, which needs no signing key at all — so leaving these two in the
 * database while moving only the RSA key would close the visible half of the problem and leave the
 * quieter half open.
 */
public class KmsSecretKeyProvider extends AbstractKmsKeyProvider {

  private final String defaultAlgorithm;

  public KmsSecretKeyProvider(
      KeycloakSession session, ComponentModel model, KmsKeyType keyType, String defaultAlgorithm) {
    super(session, model, keyType);
    this.defaultAlgorithm = defaultAlgorithm;
  }

  @Override
  protected KeyWrapper buildKey(byte[] material, KeyStatus status) {
    String algorithm = algorithm(defaultAlgorithm);
    KeyWrapper key = baseKey(status);
    key.setType(KeyType.OCT);
    key.setAlgorithm(algorithm);
    key.setSecretKey(new SecretKeySpec(material, JavaAlgorithm.getJavaAlgorithm(algorithm)));
    return key;
  }
}
