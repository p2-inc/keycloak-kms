package io.phasetwo.keycloak.kms.testsupport;

import io.phasetwo.keycloak.kms.aws.credentials.Environment;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/** An {@link Environment} backed by maps, so credential sources are testable in isolation. */
public class TestEnvironment implements Environment {

  private final Map<String, String> vars = new HashMap<>();
  private final Map<String, String> files = new HashMap<>();

  public TestEnvironment var(String name, String value) {
    vars.put(name, value);
    return this;
  }

  public TestEnvironment file(String path, String contents) {
    files.put(path, contents);
    return this;
  }

  @Override
  public String get(String name) {
    return vars.get(name);
  }

  @Override
  public String readFile(String path) throws IOException {
    String v = files.get(path);
    if (v == null) {
      throw new IOException("no such file: " + path);
    }
    return v;
  }
}
