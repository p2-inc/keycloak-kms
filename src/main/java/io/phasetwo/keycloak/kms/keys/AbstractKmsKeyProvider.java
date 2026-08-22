package io.phasetwo.keycloak.kms.keys;

import io.phasetwo.keycloak.kms.KmsConfig;
import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import java.util.stream.Stream;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;

/**
 * Shared behaviour for the envelope-mode key providers.
 *
 * <p>The shape is deliberately the same as Keycloak's own {@code AbstractRsaKeyProvider}: read
 * priority, status and algorithm from component config, produce one {@link KeyWrapper}. The only
 * difference is where the private material comes from — a KMS decrypt of a {@code kms://v1/} value,
 * cached — instead of a PEM string sitting in the same config row.
 */
@JBossLog
public abstract class AbstractKmsKeyProvider implements KeyProvider {

  protected final KeycloakSession session;
  protected final ComponentModel model;
  protected final String realmId;
  protected final KmsKeyType keyType;
  private final KeyCache cache;

  protected AbstractKmsKeyProvider(
      KeycloakSession session, ComponentModel model, KmsKeyType keyType) {
    this.session = session;
    this.model = model;
    this.keyType = keyType;
    // getContext().getRealm() is null on some administrative paths; the component's parent is the
    // realm id in every case, and it is what the material was sealed against.
    this.realmId =
        session.getContext().getRealm() != null
            ? session.getContext().getRealm().getId()
            : model.getParentId();
    this.cache = new KeyCache(KmsConfig.cacheTtlMillis());
  }

  @Override
  public Stream<KeyWrapper> getKeysStream() {
    KeyStatus status =
        KeyStatus.from(
            model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true));
    if (status == KeyStatus.DISABLED) {
      // No KMS call for a key that is not in use. This is the state the migrator leaves a legacy
      // provider in, and it is also how an operator parks a key before deleting it — neither should
      // cost a decrypt, and neither should be able to fail startup.
      return Stream.empty();
    }

    String wrapped = model.get(KmsAttributes.WRAPPED_MATERIAL);
    if (wrapped == null || wrapped.isBlank()) {
      throw new KmsException(
          "key provider "
              + model.getId()
              + " in realm "
              + realmId
              + " has no wrapped material. It was not created by this extension, or its config was"
              + " edited by hand.");
    }

    KeyWrapper key =
        cache.get(realmId, model.getId(), wrapped, () -> buildKey(unwrap(wrapped), status));
    return Stream.of(key);
  }

  /** Decrypt this provider's material. */
  protected byte[] unwrap(String wrappedValue) {
    KmsProvider kms = session.getProvider(KmsProvider.class);
    if (kms == null) {
      throw new KmsException(
          "no KMS backend is configured, but realm "
              + realmId
              + " has KMS-backed keys. Set --spi-kms--provider (aws or local). Starting without it"
              + " would mean this realm silently cannot issue tokens.");
    }
    String kid = model.get(Attributes.KID_KEY);
    return kms.decrypt(
        model.get(KmsAttributes.KMS_KEY_ID),
        WrappedMaterial.decode(wrappedValue),
        EncryptionContext.forKey(realmId, kid, keyType.contextValue()));
  }

  /** Build the Keycloak key from freshly unwrapped material. Called once per cache miss. */
  protected abstract KeyWrapper buildKey(byte[] material, KeyStatus status);

  /** Fill in everything that does not depend on the key type. */
  protected KeyWrapper baseKey(KeyStatus status) {
    KeyWrapper key = new KeyWrapper();
    key.setProviderId(model.getId());
    key.setProviderPriority(model.get(Attributes.PRIORITY_KEY, 0L));
    key.setKid(model.get(Attributes.KID_KEY));
    key.setUse(keyType.use());
    key.setStatus(status);
    return key;
  }

  protected String algorithm(String fallback) {
    return model.get(Attributes.ALGORITHM_KEY, fallback);
  }

  @Override
  public void close() {}
}
