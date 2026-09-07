package io.phasetwo.keycloak.kms.aws;

/**
 * One source of AWS credentials.
 *
 * <p>Implementations return {@code null} from {@link #resolveOrNull()} when they are simply not
 * applicable — no environment variable set, no metadata service present — and throw only when they
 * are clearly the intended source but cannot deliver. That distinction is what lets {@link
 * io.phasetwo.keycloak.kms.aws.credentials.AwsCredentialsProviderChain} fall through quietly on a
 * laptop and fail loudly in a pod that was meant to have a role.
 */
public interface AwsCredentialsProvider {

  /** Credentials, or null if this source does not apply here. */
  AwsCredentials resolveOrNull();

  /** A short name used in startup logs so an operator can see which source won. */
  String name();

  /** Credentials, or an exception naming what was tried. */
  default AwsCredentials resolve() {
    AwsCredentials c = resolveOrNull();
    if (c == null) {
      throw new io.phasetwo.keycloak.kms.spi.KmsException("no AWS credentials from " + name());
    }
    return c;
  }
}
