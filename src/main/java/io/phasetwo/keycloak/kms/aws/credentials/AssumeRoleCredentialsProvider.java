package io.phasetwo.keycloak.kms.aws.credentials;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsCredentialsProvider;
import io.phasetwo.keycloak.kms.aws.AwsSigV4Signer;
import io.phasetwo.keycloak.kms.spi.KmsException;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Assume a role, usually in another AWS account, on top of whatever identity the server already
 * has: STS {@code AssumeRole}, signed with the base credentials.
 *
 * <p>This is how a Keycloak running in one account uses a KMS key that its owner keeps in another,
 * without the owner minting an access key: the owner creates a role that may use the key and trusts
 * the Keycloak's identity, optionally behind an external id, and the server is configured with
 * {@code --spi-kms--aws--role-arn}. Revoking access is then the owner's change alone.
 *
 * <p>The base credentials come from the standard chain (static config, environment, Pod Identity,
 * ECS, IRSA, instance profile), so the base identity is whatever the server would otherwise use
 * directly. Once a role ARN is configured, this is the only source: a failure to assume the role
 * stops the server rather than falling back to the base identity, which would quietly call KMS as
 * someone the key's owner never granted.
 */
public class AssumeRoleCredentialsProvider implements AwsCredentialsProvider {

  /** STS's own constraint on RoleSessionName. */
  private static final Pattern SESSION_NAME = Pattern.compile("[\\w+=,.@-]{2,64}");

  private final AwsCredentialsProvider base;
  private final String roleArn;
  private final String externalId;
  private final String sessionName;
  private final int durationSeconds;
  private final String region;
  private final URI endpoint;
  private final String host;
  private final HttpClient http;

  /**
   * @param base where the credentials that call STS come from
   * @param roleArn the role to assume
   * @param externalId the role's sts:ExternalId condition, or null
   * @param sessionName shows in the key owner's CloudTrail; null for {@code keycloak-kms}
   * @param durationSeconds requested session length, 900 to the role's maximum; 0 for one hour
   * @param region the STS region; the regional endpoint is used, as AWS recommends
   * @param endpointOverride for LocalStack and tests, or null
   */
  public AssumeRoleCredentialsProvider(
      AwsCredentialsProvider base,
      String roleArn,
      String externalId,
      String sessionName,
      int durationSeconds,
      String region,
      String endpointOverride) {
    if (roleArn == null || roleArn.isBlank()) {
      throw new IllegalArgumentException("roleArn is required");
    }
    this.base = base;
    this.roleArn = roleArn.trim();
    this.externalId = externalId == null || externalId.isBlank() ? null : externalId.trim();
    this.sessionName =
        sessionName == null || sessionName.isBlank() ? "keycloak-kms" : sessionName.trim();
    if (!SESSION_NAME.matcher(this.sessionName).matches()) {
      throw new KmsException(
          "keycloak-kms: role session name '"
              + this.sessionName
              + "' is not valid for STS: 2 to 64 characters of letters, digits and +=,.@_-");
    }
    if (durationSeconds != 0 && (durationSeconds < 900 || durationSeconds > 43200)) {
      throw new KmsException(
          "keycloak-kms: role session duration must be between 900 and 43200 seconds, got "
              + durationSeconds);
    }
    this.durationSeconds = durationSeconds == 0 ? 3600 : durationSeconds;
    this.region = region;
    this.endpoint =
        URI.create(
            endpointOverride != null && !endpointOverride.isBlank()
                ? endpointOverride
                : "https://sts." + region + ".amazonaws.com");
    this.host =
        endpoint.getPort() > 0 ? endpoint.getHost() + ":" + endpoint.getPort() : endpoint.getHost();
    this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
  }

  @Override
  public AwsCredentials resolveOrNull() {
    AwsCredentials baseCredentials;
    try {
      baseCredentials = base.resolve();
    } catch (RuntimeException e) {
      throw new KmsException(
          "keycloak-kms: cannot assume "
              + roleArn
              + " because the server has no AWS identity to assume it with. "
              + e.getMessage(),
          e);
    }

    StringBuilder form =
        new StringBuilder("Action=AssumeRole&Version=2011-06-15")
            .append("&RoleArn=")
            .append(enc(roleArn))
            .append("&RoleSessionName=")
            .append(enc(sessionName))
            .append("&DurationSeconds=")
            .append(durationSeconds);
    if (externalId != null) {
      form.append("&ExternalId=").append(enc(externalId));
    }
    String body = form.toString();

    Map<String, String> headers =
        AwsSigV4Signer.sign(
            baseCredentials,
            region,
            "sts",
            host,
            "/",
            Map.of("content-type", "application/x-www-form-urlencoded; charset=utf-8"),
            body,
            ZonedDateTime.now(ZoneOffset.UTC));

    HttpRequest.Builder request =
        HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(5))
            .header("Accept", "application/xml")
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
    // The JDK client sets Host itself and refuses it as a header; it is still what was signed.
    headers.forEach(
        (k, v) -> {
          if (!k.equalsIgnoreCase("host")) {
            request.header(k, v);
          }
        });

    try {
      HttpResponse<String> r = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() / 100 != 2) {
        throw new KmsException(
            "STS AssumeRole for "
                + roleArn
                + " as "
                + baseCredentials.source()
                + " returned HTTP "
                + r.statusCode()
                + ": "
                + r.body()
                + " — check that the role's trust policy names this server's identity"
                + (externalId == null ? "" : " and the same external id")
                + ", and that the identity may call sts:AssumeRole on it");
      }
      return StsCredentialsXml.parse(r.body(), name());
    } catch (IOException e) {
      throw new KmsException("could not reach STS at " + endpoint, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new KmsException("interrupted calling STS", e);
    }
  }

  @Override
  public String name() {
    return "assume-role";
  }

  /** For the startup log line: the role, and the identity that assumed it. */
  public String describe() {
    String b =
        base instanceof AwsCredentialsProviderChain chain && chain.resolvedSource() != null
            ? chain.resolvedSource()
            : base.name();
    return "assume-role " + roleArn + " via " + b;
  }

  private static String enc(String v) {
    return URLEncoder.encode(v, StandardCharsets.UTF_8);
  }
}
