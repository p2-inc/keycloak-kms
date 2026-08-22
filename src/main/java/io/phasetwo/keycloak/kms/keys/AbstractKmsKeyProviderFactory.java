package io.phasetwo.keycloak.kms.keys;

import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import java.util.Arrays;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Shared behaviour for the envelope-mode key provider factories: validate config, and generate
 * material the first time, sealing it before it is ever persisted.
 */
@JBossLog
public abstract class AbstractKmsKeyProviderFactory implements KeyProviderFactory<KeyProvider> {

  protected abstract KmsKeyType keyType();

  /** Mint fresh material and write kid, public material and {@code wrappedMaterial} into config. */
  protected abstract void generate(KeycloakSession session, RealmModel realm, ComponentModel model);

  @Override
  public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
      throws ComponentValidationException {
    ConfigurationValidationHelper.check(model).checkLong(Attributes.PRIORITY_PROPERTY, false);

    if (hasMaterial(model)) {
      return;
    }

    // The admin console round-trips a component's whole config on save, and only renders the
    // properties a factory declares. A console (or a client) that drops an undeclared value would
    // otherwise land here on an unrelated edit — a priority change, say — and stock Keycloak's
    // answer is to silently regenerate, which would mint a new kid and invalidate every live token.
    // Carrying the stored material forward turns that into a no-op.
    ComponentModel stored = model.getId() == null ? null : realm.getComponent(model.getId());
    if (stored != null && hasMaterial(stored)) {
      log.debugf(
          "kms: carrying existing material forward for component %s in realm %s rather than"
              + " regenerating (the update did not include it)",
          model.getId(), realm.getName());
      carryForward(stored, model);
      return;
    }

    generate(session, realm, model);
  }

  private static boolean hasMaterial(ComponentModel model) {
    String v = model.get(KmsAttributes.WRAPPED_MATERIAL);
    return v != null && !v.isBlank();
  }

  private static void carryForward(ComponentModel from, ComponentModel to) {
    for (String key :
        List.of(
            KmsAttributes.WRAPPED_MATERIAL,
            KmsAttributes.PUBLIC_KEY,
            Attributes.KID_KEY,
            Attributes.CERTIFICATE_KEY)) {
      String v = from.get(key);
      if (v != null && to.get(key) == null) {
        to.put(key, v);
      }
    }
  }

  /**
   * Encrypt material and store it, then prove it can be read back before returning.
   *
   * <p>The read-back is not paranoia about KMS. It catches the cases that actually happen: an
   * encryption context assembled differently on the write and read paths, a per-component key id
   * that the decrypt path does not pass through, a backend whose ciphertext does not survive the
   * {@code kms://v1/} round trip. Every one of those produces a key that works until the process
   * restarts, and then locks a realm out.
   */
  protected void seal(
      KeycloakSession session, ComponentModel model, String realmId, String kid, byte[] material) {
    KmsProvider kms = kms(session);
    EncryptionContext context = EncryptionContext.forKey(realmId, kid, keyType().contextValue());
    String keyId = model.get(KmsAttributes.KMS_KEY_ID);

    String encoded = WrappedMaterial.encode(kms.encrypt(keyId, material, context));

    byte[] readBack;
    try {
      readBack = kms.decrypt(keyId, WrappedMaterial.decode(encoded), context);
    } catch (RuntimeException e) {
      throw new ComponentValidationException(
          "keycloak-kms sealed this key but could not read it back, so it has not been saved: "
              + e.getMessage());
    }
    if (!Arrays.equals(material, readBack)) {
      throw new ComponentValidationException(
          "keycloak-kms read back different material than it sealed; refusing to save a key that"
              + " would not survive a restart");
    }

    model.put(KmsAttributes.WRAPPED_MATERIAL, encoded);
  }

  protected KmsProvider kms(KeycloakSession session) {
    KmsProvider kms = session.getProvider(KmsProvider.class);
    if (kms == null) {
      throw new ComponentValidationException(
          "No KMS backend is configured. Set --spi-kms--provider=aws (or local for development)"
              + " before adding a KMS-backed key provider.");
    }
    return kms;
  }

  /** A fresh kid for material that has no public key to derive one from. */
  protected static String newKid() {
    return KeycloakModelUtils.generateId();
  }

  /** Priority and the KMS key override, which every one of these factories exposes. */
  protected static List<ProviderConfigProperty> commonProperties() {
    return List.of(Attributes.PRIORITY_PROPERTY, KmsAttributes.KMS_KEY_ID_PROPERTY);
  }

  /**
   * Never create a fallback key.
   *
   * <p>Keycloak calls this when a realm has no active key for an algorithm, and stock providers
   * respond by generating one. Doing that here would quietly manufacture a KMS-backed key — and a
   * KMS call, and possibly a bill — on an ordinary request path. If a realm has no key, that is a
   * configuration problem and should look like one.
   */
  @Override
  public boolean createFallbackKeys(
      KeycloakSession session, org.keycloak.crypto.KeyUse use, String algorithm) {
    return false;
  }

  protected static void requireKms(KeycloakSession session) {
    if (session.getProvider(KmsProvider.class) == null) {
      throw new KmsException("no KMS backend configured");
    }
  }
}
