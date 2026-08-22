package io.phasetwo.keycloak.kms.keys.nativemode;

import io.phasetwo.keycloak.kms.keys.KmsAttributes;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;

/**
 * A realm key whose private half is inside the KMS and never comes out.
 *
 * <p>Everything public — the public key, the certificate, the kid — is read from component config,
 * so JWKS costs no KMS call. The private key is a {@link KmsPrivateKey} placeholder that turns each
 * {@code Signature.sign()} into one {@code kms:Sign}.
 *
 * <p>There is no cache here and nothing to cache: the point of this mode is that no key material
 * ever exists in this process.
 */
public class KmsNativeKeyProvider implements KeyProvider {

  private final KeycloakSession session;
  private final ComponentModel model;
  private final String keyType;
  private final String defaultAlgorithm;

  public KmsNativeKeyProvider(
      KeycloakSession session, ComponentModel model, String keyType, String defaultAlgorithm) {
    this.session = session;
    this.model = model;
    this.keyType = keyType;
    this.defaultAlgorithm = defaultAlgorithm;
  }

  @Override
  public Stream<KeyWrapper> getKeysStream() {
    KeyStatus status =
        KeyStatus.from(
            model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true));
    if (status == KeyStatus.DISABLED) {
      return Stream.empty();
    }

    String keyId = model.get(KmsAttributes.KMS_KEY_ID);
    if (keyId == null || keyId.isBlank()) {
      throw new KmsException(
          "native key provider "
              + model.getId()
              + " has no kmsKeyId; there is no default for a"
              + " non-extractable signing key");
    }

    KmsProvider kms = session.getProvider(KmsProvider.class);
    if (kms == null) {
      throw new KmsException(
          "no KMS backend is configured, but this realm has a native (sign-in-KMS) key provider");
    }

    KeyWrapper key = new KeyWrapper();
    key.setProviderId(model.getId());
    key.setProviderPriority(model.get(Attributes.PRIORITY_KEY, 0L));
    key.setKid(model.get(Attributes.KID_KEY));
    key.setUse(KeyUse.SIG);
    key.setStatus(status);
    key.setType(keyType);
    key.setAlgorithm(model.get(Attributes.ALGORITHM_KEY, defaultAlgorithm));
    key.setPublicKey(publicKey());
    key.setPrivateKey(new KmsPrivateKey(kms, keyId, keyType));

    String certificatePem = model.get(Attributes.CERTIFICATE_KEY);
    if (certificatePem != null && !certificatePem.isBlank()) {
      X509Certificate certificate = PemUtils.decodeCertificate(certificatePem);
      key.setCertificate(certificate);
    }
    return Stream.of(key);
  }

  private PublicKey publicKey() {
    String encoded = model.get(KmsAttributes.PUBLIC_KEY);
    if (encoded == null || encoded.isBlank()) {
      throw new KmsException(
          "native key provider " + model.getId() + " has no cached public key; recreate it");
    }
    try {
      return KeyFactory.getInstance(KeyType.EC.equals(keyType) ? "EC" : "RSA")
          .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(encoded)));
    } catch (GeneralSecurityException e) {
      throw new KmsException("stored public key for " + model.getId() + " is unreadable", e);
    }
  }

  @Override
  public void close() {}
}
