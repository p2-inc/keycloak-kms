package io.phasetwo.keycloak.kms.testsupport;

import io.phasetwo.keycloak.kms.keys.envelope.KmsAesKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsHmacKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaEncKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaKeyProviderFactory;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * An in-memory realm with a working component store.
 *
 * <p>Faithful on the one behaviour the migrator depends on: {@code addComponentModel} runs the
 * factory's {@code validateConfiguration} before persisting, exactly as {@code RealmAdapter} does.
 * That is what generates and seals material for a rotated key, so a fake that merely stored the
 * model would make the rotation tests prove nothing.
 */
public class FakeRealm {

  private static final Map<String, KeyProviderFactory<?>> FACTORIES =
      Map.of(
          KmsRsaKeyProviderFactory.ID, new KmsRsaKeyProviderFactory(),
          KmsRsaEncKeyProviderFactory.ID, new KmsRsaEncKeyProviderFactory(),
          KmsHmacKeyProviderFactory.ID, new KmsHmacKeyProviderFactory(),
          KmsAesKeyProviderFactory.ID, new KmsAesKeyProviderFactory());

  private final String id;
  private final String name;
  private final Map<String, ComponentModel> components = new LinkedHashMap<>();
  private final RealmModel model;
  private KeycloakSession session;

  public FakeRealm(String id, String name) {
    this.id = id;
    this.name = name;
    this.model = buildProxy();
  }

  public RealmModel model() {
    return model;
  }

  public String id() {
    return id;
  }

  /** Must be set before any component is added, so validation can reach the KMS. */
  public void setSession(KeycloakSession session) {
    this.session = session;
  }

  public List<ComponentModel> components() {
    return new ArrayList<>(components.values());
  }

  public ComponentModel component(String componentId) {
    return components.get(componentId);
  }

  /** Put a component straight into the store, bypassing validation — used to seed legacy keys. */
  public ComponentModel seed(String providerId, Map<String, String> config) {
    ComponentModel m = new ComponentModel();
    m.setId(UUID.randomUUID().toString());
    m.setName(providerId);
    m.setParentId(id);
    m.setProviderId(providerId);
    m.setProviderType(KeyProvider.class.getName());
    MultivaluedHashMap<String, String> c = new MultivaluedHashMap<>();
    config.forEach(c::putSingle);
    m.setConfig(c);
    components.put(m.getId(), m);
    return m;
  }

  private RealmModel buildProxy() {
    return (RealmModel)
        Proxy.newProxyInstance(
            FakeRealm.class.getClassLoader(),
            new Class<?>[] {RealmModel.class},
            (proxy, method, args) -> {
              switch (method.getName()) {
                case "getId":
                  return id;
                case "getName":
                  return name;
                case "getComponent":
                  return components.get((String) args[0]);
                case "getComponentsStream":
                  return componentsStream(args);
                case "addComponentModel":
                  return add((ComponentModel) args[0]);
                case "updateComponent":
                  {
                    ComponentModel m = (ComponentModel) args[0];
                    components.put(m.getId(), m);
                    return null;
                  }
                case "removeComponent":
                  components.remove(((ComponentModel) args[0]).getId());
                  return null;
                case "hashCode":
                  return System.identityHashCode(proxy);
                case "equals":
                  return proxy == args[0];
                case "toString":
                  return "FakeRealm[" + name + "]";
                default:
                  throw new UnsupportedOperationException(
                      "FakeRealm does not implement RealmModel." + method.getName());
              }
            });
  }

  private Object componentsStream(Object[] args) {
    List<ComponentModel> all = new ArrayList<>(components.values());
    if (args == null || args.length == 0) {
      return all.stream();
    }
    String parentId = (String) args[0];
    String providerType = args.length > 1 ? (String) args[1] : null;
    return all.stream()
        .filter(c -> parentId == null || parentId.equals(c.getParentId()))
        .filter(c -> providerType == null || providerType.equals(c.getProviderType()));
  }

  /** What RealmAdapter.addComponentModel does: validate through the factory, then persist. */
  private ComponentModel add(ComponentModel m) {
    if (m.getId() == null) {
      m.setId(UUID.randomUUID().toString());
    }
    KeyProviderFactory<?> factory = FACTORIES.get(m.getProviderId());
    if (factory != null) {
      if (session == null) {
        throw new IllegalStateException("FakeRealm.setSession must be called before adding");
      }
      factory.validateConfiguration(session, model, m);
    }
    components.put(m.getId(), m);
    return m;
  }
}
