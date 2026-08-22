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
 * Credentials from a container credential endpoint — both flavours.
 *
 * <ul>
 *   <li><strong>ECS task role:</strong> {@code AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}, resolved
 *       against the fixed link-local address {@code 169.254.170.2}.
 *   <li><strong>EKS Pod Identity:</strong> {@code AWS_CONTAINER_CREDENTIALS_FULL_URI} plus a bearer
 *       token read from {@code AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE}.
 * </ul>
 *
 * <p>These are one source rather than two because they are the same protocol with different ways of
 * naming the endpoint, and because EKS Pod Identity — which is what a modern EKS cluster uses — is
 * the flavour most likely to be in play and the one an AWS-SDK-free extension is most likely to
 * have forgotten.
 */
public class ContainerCredentialsProvider implements AwsCredentialsProvider {

  private static final String ECS_HOST = "http://169.254.170.2";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final Environment env;
  private final HttpClient http;
  private final String ecsHostOverride;

  public ContainerCredentialsProvider(Environment env) {
    this(env, null);
  }

  ContainerCredentialsProvider(Environment env, String ecsHostOverride) {
    this.env = env;
    this.ecsHostOverride = ecsHostOverride;
    this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
  }

  @Override
  public AwsCredentials resolveOrNull() {
    String uri;
    String authToken = null;

    if (env.has("AWS_CONTAINER_CREDENTIALS_FULL_URI")) {
      uri = env.get("AWS_CONTAINER_CREDENTIALS_FULL_URI");
      authToken = readAuthToken();
    } else if (env.has("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) {
      uri =
          (ecsHostOverride != null ? ecsHostOverride : ECS_HOST)
              + env.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
    } else {
      return null;
    }

    HttpRequest.Builder b =
        HttpRequest.newBuilder(URI.create(uri)).timeout(Duration.ofSeconds(3)).GET();
    if (authToken != null) {
      b.header("Authorization", authToken);
    }

    try {
      HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() / 100 != 2) {
        throw new KmsException(
            "container credential endpoint returned HTTP " + r.statusCode() + ": " + r.body());
      }
      JsonNode j = MAPPER.readTree(r.body());
      return new AwsCredentials(
          j.path("AccessKeyId").asText(),
          j.path("SecretAccessKey").asText(),
          j.path("Token").asText(null),
          j.hasNonNull("Expiration") ? Instant.parse(j.get("Expiration").asText()) : null,
          name());
    } catch (IOException e) {
      throw new KmsException("could not read container credentials from " + uri, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new KmsException("interrupted reading container credentials", e);
    }
  }

  private String readAuthToken() {
    // The file form is what EKS Pod Identity projects; the inline variable is the older shape.
    String file = env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
    if (file != null && !file.isBlank()) {
      try {
        return env.readFile(file);
      } catch (IOException e) {
        throw new KmsException("could not read AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE " + file, e);
      }
    }
    return env.get("AWS_CONTAINER_AUTHORIZATION_TOKEN");
  }

  @Override
  public String name() {
    return env.has("AWS_CONTAINER_CREDENTIALS_FULL_URI") ? "pod-identity" : "ecs-task-role";
  }
}
