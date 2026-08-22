package io.phasetwo.keycloak.kms.migration;

import io.phasetwo.keycloak.kms.keys.KmsAttributes;
import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import io.phasetwo.keycloak.kms.keys.envelope.KmsAesKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsHmacKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaEncKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaKeyProviderFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.Attributes;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Reads plaintext key material out of a stock Keycloak key provider.
 *
 * <p>Everything here is pinned to how Keycloak 26.7 actually stores keys, checked against the
 * shipped bytecode rather than the documentation:
 *
 * <ul>
 *   <li>RSA providers keep a PEM PKCS#8 private key in {@code privateKey} and a PEM certificate in
 *       {@code certificate}.
 *   <li>Secret providers keep a Base64<em>Url</em> secret in {@code secret} — not standard base64,
 *       which is the kind of detail that produces a key that is subtly the wrong bytes.
 *   <li>The kid is {@code config.kid} when present, and otherwise the RFC 7638 thumbprint of the
 *       public key. Reproducing that exactly is what lets a migrated realm keep its JWKS.
 * </ul>
 */
public final class LegacyKeyReader {

  /** What each stock provider becomes, and what to do about the ones that cannot move. */
  private static final Map<String, KmsKeyType> MIGRATABLE =
      Map.of(
          "rsa-generated", KmsKeyType.RSA,
          "rsa", KmsKeyType.RSA,
          "rsa-enc-generated", KmsKeyType.RSA_ENC,
          "rsa-enc", KmsKeyType.RSA_ENC,
          "hmac-generated", KmsKeyType.HMAC,
          "aes-generated", KmsKeyType.AES);

  private static final Map<KmsKeyType, String> TARGET_PROVIDER =
      Map.of(
          KmsKeyType.RSA, KmsRsaKeyProviderFactory.ID,
          KmsKeyType.RSA_ENC, KmsRsaEncKeyProviderFactory.ID,
          KmsKeyType.HMAC, KmsHmacKeyProviderFactory.ID,
          KmsKeyType.AES, KmsAesKeyProviderFactory.ID);

  /**
   * Stock providers this version knowingly leaves alone, and why.
   *
   * <p>Reported rather than ignored. A realm that migrates its RSA key and silently keeps an
   * unmigrated EC key still has a private key in the database, and an operator who was told
   * "migrated" would have no way to know.
   */
  private static final Map<String, String> UNSUPPORTED =
      Map.of(
          "ecdsa-generated",
              "ECDSA is not supported by envelope mode in this version, so this key's private half"
                  + " remains in the database. Track the EC envelope provider before relying on"
                  + " this realm being fully migrated.",
          "eddsa-generated",
              "AWS KMS has no Ed25519 key spec and this version has no EdDSA envelope provider, so"
                  + " this key's private half remains in the database.",
          "java-keystore",
              "This provider already keeps its material outside the database, in a keystore file."
                  + " Migrating it is possible but is not automated here.");

  private LegacyKeyReader() {}

  /** Whether this provider is one of ours already. */
  public static boolean isKmsBacked(ComponentModel model) {
    return TARGET_PROVIDER.containsValue(model.getProviderId())
        || model.getProviderId().startsWith("kms-");
  }

  /** A reason this provider cannot be migrated, or null if it can. */
  public static String unsupportedReason(ComponentModel model) {
    String known = UNSUPPORTED.get(model.getProviderId());
    if (known != null) {
      return known;
    }
    if (!MIGRATABLE.containsKey(model.getProviderId())) {
      return "Not a key provider this extension knows how to migrate.";
    }
    return null;
  }

  /** Read a stock provider's material. Only call when {@link #unsupportedReason} returned null. */
  public static LegacyKey read(ComponentModel model) {
    KmsKeyType type = MIGRATABLE.get(model.getProviderId());
    if (type == null) {
      throw new IllegalArgumentException("not a migratable provider: " + model.getProviderId());
    }
    long priority = model.get(Attributes.PRIORITY_KEY, 0L);
    String algorithm = model.get(Attributes.ALGORITHM_KEY);
    String explicitKid = model.get(Attributes.KID_KEY);

    if (type.isSecret()) {
      String secret = model.get(Attributes.SECRET_KEY);
      if (secret == null || secret.isBlank()) {
        throw new IllegalStateException(
            "provider " + model.getId() + " (" + model.getProviderId() + ") has no secret to read");
      }
      // Base64Url, not Base64. Getting this wrong yields a key of the right length and the wrong
      // bytes, which fails only when an action token is validated.
      byte[] material = Base64Url.decode(secret);
      // Stock always stores a kid for generated secrets; mint one only if a hand-built component
      // did not. Secret keys are not published in JWKS, so a new kid here is invisible externally.
      String kid = explicitKid != null ? explicitKid : KeycloakModelUtils.generateId();
      return new LegacyKey(
          type,
          TARGET_PROVIDER.get(type),
          kid,
          material,
          null,
          algorithm,
          priority,
          explicitKid != null);
    }

    String privateKeyPem = model.get(Attributes.PRIVATE_KEY_KEY);
    if (privateKeyPem == null || privateKeyPem.isBlank()) {
      throw new IllegalStateException(
          "provider " + model.getId() + " (" + model.getProviderId() + ") has no private key");
    }
    PrivateKey privateKey = PemUtils.decodePrivateKey(privateKeyPem);
    // Match AbstractRsaKeyProvider exactly: the public key it derives the kid from is extracted
    // from the private key, not taken from the certificate.
    PublicKey publicKey = KeyUtils.extractPublicKey(privateKey);
    String kid = explicitKid != null ? explicitKid : KeyUtils.createKeyId(publicKey);

    return new LegacyKey(
        type,
        TARGET_PROVIDER.get(type),
        kid,
        privateKey.getEncoded(),
        model.get(Attributes.CERTIFICATE_KEY),
        algorithm,
        priority,
        explicitKid != null);
  }

  /** The config key that holds plaintext material for this provider, for reporting. */
  public static String plaintextConfigKey(ComponentModel model) {
    KmsKeyType type = MIGRATABLE.get(model.getProviderId());
    if (type == null) {
      return null;
    }
    return type.isSecret() ? Attributes.SECRET_KEY : Attributes.PRIVATE_KEY_KEY;
  }

  /** True when this component currently holds usable plaintext key material. */
  public static boolean holdsPlaintext(ComponentModel model) {
    if (isKmsBacked(model)) {
      return false;
    }
    return notBlank(model.get(Attributes.PRIVATE_KEY_KEY))
        || notBlank(model.get(Attributes.SECRET_KEY));
  }

  static boolean notBlank(String s) {
    return s != null && !s.isBlank();
  }

  /** The provider id a given KMS key type is served by. */
  public static String targetProviderFor(KmsKeyType type) {
    String id = TARGET_PROVIDER.get(type);
    if (id == null) {
      throw new IllegalArgumentException(
          type + " has no envelope provider; native-mode keys are generate-only");
    }
    return id;
  }

  /** Config keys that must not be copied from a legacy component to a KMS one. */
  static boolean isLegacyPlaintextKey(String configKey) {
    return Attributes.PRIVATE_KEY_KEY.equals(configKey)
        || Attributes.SECRET_KEY.equals(configKey)
        || KmsAttributes.WRAPPED_MATERIAL.equals(configKey);
  }
}
