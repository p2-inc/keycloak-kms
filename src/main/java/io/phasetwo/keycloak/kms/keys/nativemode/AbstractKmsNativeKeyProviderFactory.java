package io.phasetwo.keycloak.kms.keys.nativemode;

import io.phasetwo.keycloak.kms.keys.KmsAttributes;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Shared behaviour for the native (sign-in-KMS) providers. <strong>Experimental in this
 * release.</strong>
 *
 * <p>Bring your own key. The extension neither creates nor deletes asymmetric CMKs, and the reason
 * is cost and blast radius rather than effort: an asymmetric CMK bills for as long as it exists, so
 * implicit creation would orphan a billable key every time a realm was deleted, and implicit
 * deletion would eventually schedule the destruction of a key that was still signing production
 * tokens. Neither failure is one to risk for a convenience.
 */
@JBossLog
public abstract class AbstractKmsNativeKeyProviderFactory
    implements KeyProviderFactory<KeyProvider> {

  /** {@code EC} or {@code RSA}. */
  protected abstract String keyType();

  /** e.g. {@code ES256}. */
  protected abstract String defaultAlgorithm();

  /** The KMS key-spec prefix this factory accepts, e.g. {@code ECC_}. */
  protected abstract String keySpecPrefix();

  /** Map the configured JOSE algorithm to the KMS signing algorithm. */
  protected abstract KmsSigningAlgorithm signingAlgorithm(String joseAlgorithm);

  /** Whether to mint a self-signed certificate. Stock EC providers make this optional. */
  protected boolean certificateByDefault() {
    return true;
  }

  @Override
  public KeyProvider create(KeycloakSession session, ComponentModel model) {
    return new KmsNativeKeyProvider(session, model, keyType(), defaultAlgorithm());
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // Registering here rather than lazily means the provider is in place before any request can
    // reach a native key. It accepts only KmsPrivateKey, so registering it costs nothing on a
    // server that has no native providers at all.
    KmsJcaProvider.register();
  }

  @Override
  public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model)
      throws ComponentValidationException {
    String keyId = model.get(KmsAttributes.KMS_KEY_ID);
    if (keyId == null || keyId.isBlank()) {
      throw new ComponentValidationException(
          "A native key provider needs the ARN of an asymmetric KMS key with usage SIGN_VERIFY."
              + " Create one with: aws kms create-key --key-usage SIGN_VERIFY --key-spec "
              + exampleKeySpec());
    }

    if (model.contains(KmsAttributes.PUBLIC_KEY) && model.contains(Attributes.KID_KEY)) {
      // Already set up. Re-reading the public key on every save would be a KMS call for nothing,
      // and the values cannot have changed: a CMK's public half is immutable.
      return;
    }

    KmsProvider kms = session.getProvider(KmsProvider.class);
    if (kms == null) {
      throw new ComponentValidationException(
          "No KMS backend is configured. Set --spi-kms--provider=aws.");
    }
    if (!kms.supportsNativeKeys()) {
      throw new ComponentValidationException(
          "The configured KMS backend does not support non-extractable signing keys.");
    }

    KmsKeyDescription key;
    try {
      key = kms.describe(keyId);
    } catch (RuntimeException e) {
      throw new ComponentValidationException(
          "Could not read KMS key " + keyId + ": " + e.getMessage());
    }
    if (!key.isSigning()) {
      throw new ComponentValidationException(
          "KMS key "
              + key
              + " has usage "
              + key.keyUsage()
              + ", but a native key provider needs"
              + " SIGN_VERIFY. An ENCRYPT_DECRYPT key belongs to envelope mode.");
    }
    if (!key.enabled()) {
      throw new ComponentValidationException(
          "KMS key " + key + " is disabled or pending deletion.");
    }
    if (key.keySpec() != null && !key.keySpec().startsWith(keySpecPrefix())) {
      throw new ComponentValidationException(
          "KMS key "
              + key
              + " has spec "
              + key.keySpec()
              + ", which this provider cannot use. Expected a "
              + keySpecPrefix()
              + "* key.");
    }

    PublicKey publicKey = kms.publicKey(keyId);
    String kid = model.get(Attributes.KID_KEY);
    if (kid == null || kid.isBlank()) {
      // Same derivation as every other Keycloak key: the RFC 7638 thumbprint.
      kid = KeyUtils.createKeyId(publicKey);
      model.put(Attributes.KID_KEY, kid);
    }
    model.put(KmsAttributes.PUBLIC_KEY, Base64.getEncoder().encodeToString(publicKey.getEncoded()));

    if (certificateByDefault() && !model.contains(Attributes.CERTIFICATE_KEY)) {
      X509Certificate certificate =
          SelfSignedCertMinter.mint(
              kms,
              keyId,
              publicKey,
              realm.getName(),
              signingAlgorithm(model.get(Attributes.ALGORITHM_KEY, defaultAlgorithm())));
      model.put(Attributes.CERTIFICATE_KEY, PemUtils.encodeCertificate(certificate));
    }

    warnLoudly(realm, key, kid);
  }

  /**
   * Say the three things that are otherwise discovered too late: this mode is experimental, each
   * key costs a dollar a month forever, and {@code kms:Sign} has an account-wide rate ceiling.
   */
  private void warnLoudly(RealmModel realm, KmsKeyDescription key, String kid) {
    log.warnf(
        "kms: realm '%s': native provider added (kid %s)%n"
            + "  key=%s%n"
            + "  *** NATIVE MODE IS EXPERIMENTAL IN THIS RELEASE. Envelope mode is the supported"
            + " default. ***%n"
            + "  This CMK bills for as long as it exists — this extension will never delete it.%n"
            + "  Every token this realm issues costs one kms:Sign call and adds single-digit to"
            + " low-tens of milliseconds to the token endpoint.%n"
            + "  kms:Sign draws on a per-region asymmetric-operation quota shared by your whole AWS"
            + " account. Check Service Quotas before pointing a high-volume realm at this mode.",
        realm.getName(), kid, key);
  }

  /**
   * Never create a fallback key: a native key cannot be conjured, it has to be provisioned in AWS.
   */
  @Override
  public boolean createFallbackKeys(KeycloakSession session, KeyUse use, String algorithm) {
    return false;
  }

  protected abstract String exampleKeySpec();

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property(Attributes.PRIORITY_PROPERTY)
        .property(Attributes.ENABLED_PROPERTY)
        .property(Attributes.ACTIVE_PROPERTY)
        .property()
        .name(KmsAttributes.KMS_KEY_ID)
        .label("KMS key ARN")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "ARN of an asymmetric KMS key with usage SIGN_VERIFY. Required — this extension never"
                + " creates or deletes asymmetric keys.")
        .add()
        .property(algorithmProperty())
        .build();
  }

  protected abstract ProviderConfigProperty algorithmProperty();
}
