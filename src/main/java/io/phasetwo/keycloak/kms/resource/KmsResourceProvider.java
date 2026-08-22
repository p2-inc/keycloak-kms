package io.phasetwo.keycloak.kms.resource;

import org.keycloak.models.KeycloakSession;

/** Serves {@link KmsResource} at {@code /realms/{realm}/kms}. */
public class KmsResourceProvider extends BaseRealmResourceProvider {

  public KmsResourceProvider(KeycloakSession session) {
    super(session);
  }

  @Override
  public Object getRealmResource() {
    KmsResource resource = new KmsResource(session);
    resource.setup();
    return resource;
  }
}
