package io.phasetwo.keycloak.kms.aws.credentials;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The process environment, as an interface so that credential sources are testable without mutating
 * the real one.
 *
 * <p>Also covers reading a file, because two of the six sources (web identity, EKS Pod Identity)
 * take their token from a projected file rather than a variable.
 */
public interface Environment {

  Environment SYSTEM =
      new Environment() {
        @Override
        public String get(String name) {
          return System.getenv(name);
        }

        @Override
        public String readFile(String path) throws IOException {
          return Files.readString(Path.of(path)).trim();
        }
      };

  String get(String name);

  String readFile(String path) throws IOException;

  default String get(String name, String fallback) {
    String v = get(name);
    return v == null || v.isBlank() ? fallback : v;
  }

  default boolean has(String name) {
    String v = get(name);
    return v != null && !v.isBlank();
  }
}
