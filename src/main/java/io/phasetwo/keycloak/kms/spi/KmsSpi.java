package io.phasetwo.keycloak.kms.spi;

import com.google.auto.service.AutoService;
import org.keycloak.provider.Spi;

/**
 * The {@code kms} SPI: an abstraction over a cloud key-management service.
 *
 * <p>Two families of operation live behind it, matching the two custody modes this extension
 * offers. <em>Envelope</em> mode uses {@link KmsProvider#encrypt} / {@link KmsProvider#decrypt} to
 * protect key material that Keycloak still holds and signs with in process. <em>Native</em> mode
 * uses {@link KmsProvider#sign} / {@link KmsProvider#publicKey} against a key that never leaves the
 * KMS.
 *
 * <p>A backend is free to implement only the envelope half; {@link
 * KmsProvider#supportsNativeKeys()} declares which. The bundled {@code aws} backend supports both,
 * {@code local} supports both for development but is not a KMS in any meaningful sense.
 */
@AutoService(Spi.class)
public class KmsSpi implements Spi {

  public static final String NAME = "kms";

  @Override
  public boolean isInternal() {
    return false;
  }

  @Override
  public String getName() {
    return NAME;
  }

  @Override
  public Class<? extends org.keycloak.provider.Provider> getProviderClass() {
    return KmsProvider.class;
  }

  @Override
  public Class<? extends org.keycloak.provider.ProviderFactory> getProviderFactoryClass() {
    return KmsProviderFactory.class;
  }
}
