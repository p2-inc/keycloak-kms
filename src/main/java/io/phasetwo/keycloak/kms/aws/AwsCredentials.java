package io.phasetwo.keycloak.kms.aws;

import java.time.Instant;

/**
 * A set of AWS credentials, possibly temporary.
 *
 * @param accessKeyId the access key id
 * @param secretAccessKey the secret; never logged, never surfaced in an error
 * @param sessionToken present for temporary credentials (IRSA, Pod Identity, ECS, EC2, STS), null
 *     for long-lived access keys
 * @param expiration when these stop working, or null if they do not expire
 * @param source a short human-readable origin, e.g. {@code web-identity} — this is what gets logged
 *     at startup so an operator can see which of six possible sources actually won
 */
public record AwsCredentials(
    String accessKeyId,
    String secretAccessKey,
    String sessionToken,
    Instant expiration,
    String source) {

  public static AwsCredentials longLived(
      String accessKeyId, String secretAccessKey, String source) {
    return new AwsCredentials(accessKeyId, secretAccessKey, null, null, source);
  }

  /**
   * Whether these should be refreshed.
   *
   * <p>The five-minute margin is not arbitrary: STS and the instance metadata service both hand out
   * credentials whose last minutes overlap with the next set, and a token that expires mid-request
   * surfaces as an opaque {@code InvalidClientTokenId} rather than anything that names the cause.
   */
  public boolean isExpiring() {
    return expiration != null && Instant.now().isAfter(expiration.minusSeconds(300));
  }

  /** Deliberately omits the secret and the session token. */
  @Override
  public String toString() {
    return "AwsCredentials["
        + source
        + ", accessKeyId="
        + accessKeyId
        + ", expiration="
        + expiration
        + "]";
  }
}
