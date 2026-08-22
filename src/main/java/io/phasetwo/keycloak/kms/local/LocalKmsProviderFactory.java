package io.phasetwo.keycloak.kms.local;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsProviderFactory;
import java.util.Base64;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

/**
 * Factory for the development KMS backend.
 *
 * <p>Selected with {@code --spi-kms--provider=local}. If no KEK is configured it uses a fixed,
 * published one so that {@code docker compose up} works with no setup — and warns loudly on every
 * boot, because a published KEK protects nothing.
 */
@JBossLog
@AutoService(KmsProviderFactory.class)
public class LocalKmsProviderFactory implements KmsProviderFactory {

  public static final String ID = "local";

  /**
   * A KEK that is in the source tree of a public repository. It exists so the dev environment
   * starts without ceremony, and it is worth exactly what you paid for it.
   */
  static final String DEV_KEK_BASE64 = "a2V5Y2xvYWsta21zLURFVi1PTkxZLWtlay0wMDAwMDE=";

  private volatile LocalKmsProvider provider;

  @Override
  public KmsProvider create(KeycloakSession session) {
    return provider;
  }

  @Override
  public void init(Config.Scope config) {
    String b64 = config.get("kek");
    boolean supplied = b64 != null && !b64.isBlank();
    byte[] kek = Base64.getDecoder().decode((supplied ? b64 : DEV_KEK_BASE64).trim());
    String defaultKeyId = config.get("keyId", "local-default");
    this.provider = new LocalKmsProvider(kek, defaultKeyId);

    log.warn("=".repeat(100));
    log.warn(
        "keycloak-kms is using the 'local' backend. Realm key material is encrypted with a key held"
            + " in this server's configuration, NOT in a KMS. This is for development and tests.");
    if (!supplied) {
      log.warn(
          "No KEK was configured, so the PUBLISHED development KEK is in use. Anyone with a copy of"
              + " this extension can decrypt every realm key in this database.");
    }
    log.warn("Set --spi-kms--provider=aws before this server holds anything you care about.");
    log.warn("=".repeat(100));
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {}

  @Override
  public void close() {}

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public List<ProviderConfigProperty> getConfigMetadata() {
    return ProviderConfigurationBuilder.create()
        .property()
        .name("kek")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("Base64 of a 16, 24 or 32 byte AES key. Defaults to a published development key.")
        .add()
        .property()
        .name("keyId")
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue("local-default")
        .helpText("Default key id. Prefix with ec256:/rsa2048:/etc. to make it a signing key.")
        .add()
        .build();
  }
}
