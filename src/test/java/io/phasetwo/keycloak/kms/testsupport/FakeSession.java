package io.phasetwo.keycloak.kms.testsupport;

import io.phasetwo.keycloak.kms.spi.KmsProvider;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Just enough {@link KeycloakSession} and {@link RealmModel} to exercise the key providers.
 *
 * <p>Dynamic proxies rather than a mocking framework or a real container: the providers touch four
 * methods between them, and a container per assertion would turn a sub-second suite into a
 * multi-minute one. The integration suite covers what a real Keycloak does with these; this covers
 * what they do with a KMS.
 *
 * <p>Any method not wired here throws, so a provider quietly starting to depend on more of Keycloak
 * shows up as a failure rather than as a null.
 */
public final class FakeSession {

  private FakeSession() {}

  /** A realm whose components can be registered, so the carry-forward path is testable. */
  public static RealmModel realm(String id, String name) {
    Map<String, ComponentModel> components = new HashMap<>();
    return realm(id, name, components);
  }

  public static RealmModel realm(String id, String name, Map<String, ComponentModel> components) {
    return (RealmModel)
        Proxy.newProxyInstance(
            FakeSession.class.getClassLoader(),
            new Class<?>[] {RealmModel.class},
            handler(
                Map.of(
                    "getId", args -> id,
                    "getName", args -> name,
                    "getComponent", args -> components.get((String) args[0]),
                    "toString", args -> "FakeRealm[" + name + "]")));
  }

  /** A session that resolves exactly one provider — the KMS — and one realm. */
  public static KeycloakSession session(KmsProvider kms, RealmModel realm) {
    KeycloakContext context =
        (KeycloakContext)
            Proxy.newProxyInstance(
                FakeSession.class.getClassLoader(),
                new Class<?>[] {KeycloakContext.class},
                handler(Map.of("getRealm", args -> realm)));

    return (KeycloakSession)
        Proxy.newProxyInstance(
            FakeSession.class.getClassLoader(),
            new Class<?>[] {KeycloakSession.class},
            handler(
                Map.of(
                    "getContext", args -> context,
                    "getProvider",
                        args -> args.length == 1 && args[0] == KmsProvider.class ? kms : null,
                    "toString", args -> "FakeSession")));
  }

  private interface Impl {
    Object apply(Object[] args);
  }

  private static InvocationHandler handler(Map<String, Impl> methods) {
    return (proxy, method, args) -> {
      Impl impl = methods.get(method.getName());
      if (impl != null) {
        return impl.apply(args == null ? new Object[0] : args);
      }
      switch (method.getName()) {
        case "hashCode":
          return System.identityHashCode(proxy);
        case "equals":
          return proxy == args[0];
        case "toString":
          return "Fake" + method.getDeclaringClass().getSimpleName();
        default:
          throw new UnsupportedOperationException(
              "FakeSession does not implement "
                  + method.getDeclaringClass().getSimpleName()
                  + "."
                  + method.getName()
                  + " — wire it up if the code under test now needs it");
      }
    };
  }
}
