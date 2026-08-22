package io.phasetwo.keycloak.kms.aws.credentials;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsCredentialsProvider;

/** {@code AWS_ACCESS_KEY_ID} / {@code AWS_SECRET_ACCESS_KEY} / {@code AWS_SESSION_TOKEN}. */
public class EnvironmentCredentialsProvider implements AwsCredentialsProvider {

  private final Environment env;

  public EnvironmentCredentialsProvider(Environment env) {
    this.env = env;
  }

  @Override
  public AwsCredentials resolveOrNull() {
    if (!env.has("AWS_ACCESS_KEY_ID") || !env.has("AWS_SECRET_ACCESS_KEY")) {
      return null;
    }
    return new AwsCredentials(
        env.get("AWS_ACCESS_KEY_ID"),
        env.get("AWS_SECRET_ACCESS_KEY"),
        env.get("AWS_SESSION_TOKEN"),
        null,
        name());
  }

  @Override
  public String name() {
    return "environment";
  }
}
