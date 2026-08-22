package io.phasetwo.keycloak.kms.resource;

import com.google.auto.service.AutoService;
import io.phasetwo.keycloak.kms.bootstrap.KmsBootstrap;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Registers the {@code kms} realm resource. */
@AutoService(RealmResourceProviderFactory.class)
public class KmsResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String ID = "kms";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession session) {
    return new KmsResourceProvider(session);
  }

  @Override
  public void init(Config.Scope config) {}

  /**
   * Also where the extension's optional lifecycle hooks get installed.
   *
   * <p>Not because they belong to a REST resource, but because this factory is always registered
   * and {@code postInit} is the only startup hook Keycloak gives an extension. See {@link
   * KmsBootstrap}.
   */
  @Override
  public void postInit(KeycloakSessionFactory factory) {
    KmsBootstrap.install(factory);
  }

  @Override
  public void close() {}
}
