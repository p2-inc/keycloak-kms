package io.phasetwo.keycloak.kms.testsupport;

import org.keycloak.common.crypto.CryptoIntegration;

/**
 * Boots Keycloak's crypto layer for tests that run outside a server.
 *
 * <p>{@code KeyUtils}, {@code CertificateUtils} and even some {@code Attributes} constants resolve
 * through {@link CryptoIntegration}, which throws "Illegal state. Please init first" until a
 * provider is registered. In a real server Quarkus does this at boot; here nothing does.
 */
public final class Crypto {

  private static volatile boolean initialised;

  private Crypto() {}

  public static synchronized void init() {
    if (!initialised) {
      CryptoIntegration.init(Crypto.class.getClassLoader());
      initialised = true;
    }
  }
}
