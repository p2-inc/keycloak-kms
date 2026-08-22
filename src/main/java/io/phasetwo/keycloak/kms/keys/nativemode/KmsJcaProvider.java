package io.phasetwo.keycloak.kms.keys.nativemode;

import java.security.Provider;
import java.security.Security;
import lombok.extern.jbosslog.JBossLog;

/**
 * A JCA provider that signs through a KMS, and the reason native mode needs no fork of Keycloak.
 *
 * <p>Keycloak's {@code AsymmetricSignatureSignerContext} does exactly this:
 *
 * <pre>{@code
 * Signature.getInstance(javaAlgorithm).initSign(key.getPrivateKey())
 * }</pre>
 *
 * <p>No provider is named, so the JDK defers provider selection until {@code initSign} and picks
 * the first registered provider that accepts the key. SunEC and SunRsaSign both advertise {@code
 * SupportedKeyClasses}, so they are skipped for a {@link KmsPrivateKey} — which implements neither
 * {@code ECPrivateKey} nor {@code RSAPrivateKey} — and this provider is reached instead.
 *
 * <p>Registered <strong>last</strong>, and it accepts nothing but a {@link KmsPrivateKey}. Ordinary
 * realm keys, TLS, and everything else in the process continue to use the JDK's own providers, and
 * {@code KmsJcaProviderTest} asserts exactly that.
 */
@JBossLog
public final class KmsJcaProvider extends Provider {

  public static final String NAME = "KeycloakKms";

  private static volatile boolean registered;

  private KmsJcaProvider() {
    super(NAME, "1.0", "Signs through a cloud KMS with non-extractable keys");

    // ECDSA first: it is the default for native mode, cheaper and faster inside KMS than RSA.
    put("Signature.SHA256withECDSA", KmsSignatureSpi.EcdsaSha256.class.getName());
    put("Signature.SHA384withECDSA", KmsSignatureSpi.EcdsaSha384.class.getName());
    put("Signature.SHA512withECDSA", KmsSignatureSpi.EcdsaSha512.class.getName());

    put("Signature.SHA256withRSA", KmsSignatureSpi.RsaSha256.class.getName());
    put("Signature.SHA384withRSA", KmsSignatureSpi.RsaSha384.class.getName());
    put("Signature.SHA512withRSA", KmsSignatureSpi.RsaSha512.class.getName());
    put("Signature.RSASSA-PSS", KmsSignatureSpi.RsaPss.class.getName());
  }

  /**
   * Register once, at the end of the provider list.
   *
   * <p>Appending rather than inserting is deliberate and is the whole safety story: at the end,
   * this provider is only ever consulted for keys every built-in provider has already refused.
   */
  public static synchronized void register() {
    if (registered) {
      return;
    }
    if (Security.getProvider(NAME) == null) {
      int position = Security.addProvider(new KmsJcaProvider());
      log.infof(
          "kms: registered the %s JCA provider at position %d; it accepts only non-extractable"
              + " KMS-held keys",
          NAME, position);
    }
    registered = true;
  }

  /** Tests only. */
  static synchronized void unregister() {
    Security.removeProvider(NAME);
    registered = false;
  }
}
