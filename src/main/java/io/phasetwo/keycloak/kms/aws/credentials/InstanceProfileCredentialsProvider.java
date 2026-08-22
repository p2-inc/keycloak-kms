package io.phasetwo.keycloak.kms.aws.credentials;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsCredentialsProvider;
import io.phasetwo.keycloak.kms.spi.KmsException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

/**
 * EC2 instance profile credentials, over IMDSv2.
 *
 * <p>IMDSv2 only: the token handshake is mandatory here even though IMDSv1 would be one request
 * fewer. IMDSv1's lack of a token is what makes an SSRF in any process on the box a credential
 * disclosure, and an extension whose job is protecting keys should not be the reason a fleet keeps
 * IMDSv1 enabled.
 *
 * <p>The timeouts are deliberately short. This is the last source in the chain, so on anything that
 * is not an EC2 instance it is a guaranteed miss — and a slow miss here delays every startup.
 */
public class InstanceProfileCredentialsProvider implements AwsCredentialsProvider {

  private static final String IMDS = "http://169.254.169.254";
  private static final Duration TIMEOUT = Duration.ofSeconds(1);
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final HttpClient http;
  private final String base;

  public InstanceProfileCredentialsProvider() {
    this(IMDS);
  }

  InstanceProfileCredentialsProvider(String base) {
    this.base = base;
    this.http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
  }

  @Override
  public AwsCredentials resolveOrNull() {
    String token;
    try {
      HttpResponse<String> t =
          http.send(
              HttpRequest.newBuilder(URI.create(base + "/latest/api/token"))
                  .timeout(TIMEOUT)
                  .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
                  .PUT(HttpRequest.BodyPublishers.noBody())
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      if (t.statusCode() != 200) {
        return null;
      }
      token = t.body().trim();
    } catch (IOException e) {
      // Not on EC2, or IMDS is blocked. Not an error — the chain simply moves on.
      return null;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return null;
    }

    try {
      HttpResponse<String> roles = get(base + "/latest/meta-data/iam/security-credentials/", token);
      if (roles.statusCode() != 200 || roles.body().isBlank()) {
        return null;
      }
      // The listing is newline-separated; an instance profile holds exactly one role in practice.
      String role = roles.body().lines().findFirst().orElseThrow().trim();

      HttpResponse<String> creds =
          get(base + "/latest/meta-data/iam/security-credentials/" + role, token);
      if (creds.statusCode() != 200) {
        throw new KmsException(
            "IMDS returned HTTP " + creds.statusCode() + " for instance profile role " + role);
      }
      JsonNode j = MAPPER.readTree(creds.body());
      return new AwsCredentials(
          j.path("AccessKeyId").asText(),
          j.path("SecretAccessKey").asText(),
          j.path("Token").asText(null),
          j.hasNonNull("Expiration") ? Instant.parse(j.get("Expiration").asText()) : null,
          name());
    } catch (IOException e) {
      throw new KmsException("could not read instance profile credentials from IMDS", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new KmsException("interrupted reading IMDS", e);
    }
  }

  private HttpResponse<String> get(String url, String token)
      throws IOException, InterruptedException {
    return http.send(
        HttpRequest.newBuilder(URI.create(url))
            .timeout(TIMEOUT)
            .header("X-aws-ec2-metadata-token", token)
            .GET()
            .build(),
        HttpResponse.BodyHandlers.ofString());
  }

  @Override
  public String name() {
    return "instance-profile";
  }
}
