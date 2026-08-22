package io.phasetwo.keycloak.kms.keys.envelope;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.kms.keys.AbstractKmsKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/** {@code kms-hmac-generated} — the KMS-backed replacement for {@code hmac-generated}. */
@JBossLog
@AutoService(KeyProviderFactory.class)
public class KmsHmacKeyProviderFactory extends AbstractKmsKeyProviderFactory {

  public static final String ID = "kms-hmac-generated";

  /** Bytes, matching stock's default for HMAC secrets. */
  public static final int DEFAULT_SECRET_SIZE = 64;

  private static final SecureRandom RANDOM = new SecureRandom();

  @Override
  public String getId() {
    return ID;
  }

  @Override
  protected KmsKeyType keyType() {
    return KmsKeyType.HMAC;
  }

  protected String defaultAlgorithm() {
    return Algorithm.HS256;
  }

  protected int defaultSecretSize() {
    return DEFAULT_SECRET_SIZE;
  }

  @Override
  public KeyProvider create(KeycloakSession session, ComponentModel model) {
    return new KmsSecretKeyProvider(session, model, keyType(), defaultAlgorithm());
  }

  @Override
  protected void generate(KeycloakSession session, RealmModel realm, ComponentModel model) {
    int size = model.get(Attributes.SECRET_SIZE_KEY, defaultSecretSize());
    if (size < 16 || size > 512) {
      throw new ComponentValidationException("secret size must be between 16 and 512 bytes");
    }

    byte[] secret = new byte[size];
    RANDOM.nextBytes(secret);
    // A secret key has no public half to derive a kid from, so mint one. Stock does the same, which
    // is why a migrated secret key can keep the kid it already had.
    String kid = newKid();
    model.put(Attributes.KID_KEY, kid);

    try {
      seal(session, model, realm.getId(), kid, secret);
    } finally {
      Arrays.fill(secret, (byte) 0);
    }

    log.infof(
        "kms: generated a %d-byte %s secret for realm %s (kid %s), stored as KMS ciphertext",
        size, keyType().contextValue(), realm.getName(), kid);
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    ProviderConfigurationBuilder b = ProviderConfigurationBuilder.create();
    commonProperties().forEach(b::property);
    b.property(Attributes.ENABLED_PROPERTY)
        .property(Attributes.ACTIVE_PROPERTY)
        .property(Attributes.SECRET_SIZE_PROPERTY);
    ProviderConfigProperty algorithm = algorithmProperty();
    if (algorithm != null) {
      b.property(algorithm);
    }
    return b.build();
  }

  protected ProviderConfigProperty algorithmProperty() {
    return Attributes.HS_ALGORITHM_PROPERTY;
  }

  @Override
  public String getHelpText() {
    return "HMAC secrets generated in memory and stored encrypted under a cloud KMS key. Used for"
        + " action tokens and the identity cookie.";
  }
}
