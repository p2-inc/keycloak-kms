package io.phasetwo.keycloak.kms.aws.credentials;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsCredentialsProvider;

/**
 * Credentials given directly in the extension's configuration.
 *
 * <p>Documented, supported, and discouraged: putting a long-lived AWS secret in the Keycloak
 * configuration to protect keys in the Keycloak database moves the problem rather than solving it.
 * It exists because some environments genuinely have no role to assume.
 */
public class StaticCredentialsProvider implements AwsCredentialsProvider {

  private final AwsCredentials credentials;

  public StaticCredentialsProvider(
      String accessKeyId, String secretAccessKey, String sessionToken) {
    this.credentials =
        accessKeyId == null
                || accessKeyId.isBlank()
                || secretAccessKey == null
                || secretAccessKey.isBlank()
            ? null
            : new AwsCredentials(accessKeyId, secretAccessKey, sessionToken, null, name());
  }

  @Override
  public AwsCredentials resolveOrNull() {
    return credentials;
  }

  @Override
  public String name() {
    return "static-config";
  }
}
