package io.phasetwo.keycloak.kms.aws.credentials;

import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsCredentialsProvider;
import io.phasetwo.keycloak.kms.spi.KmsException;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * IRSA: exchange a projected Kubernetes service-account token for AWS credentials via STS {@code
 * AssumeRoleWithWebIdentity}.
 *
 * <p>Triggered by {@code AWS_ROLE_ARN} plus {@code AWS_WEB_IDENTITY_TOKEN_FILE}, which is exactly
 * what the EKS pod-identity webhook injects when a service account carries the {@code
 * eks.amazonaws.com/role-arn} annotation. For most people deploying this extension on EKS, this is
 * the source that will actually be used.
 *
 * <p>{@code AssumeRoleWithWebIdentity} is one of the few AWS calls that takes no SigV4 signature —
 * the web identity token <em>is</em> the credential — which is why this needs no bootstrapping.
 */
public class WebIdentityCredentialsProvider implements AwsCredentialsProvider {

  private final Environment env;
  private final HttpClient http;
  private final String stsEndpointOverride;

  public WebIdentityCredentialsProvider(Environment env) {
    this(env, null);
  }

  WebIdentityCredentialsProvider(Environment env, String stsEndpointOverride) {
    this.env = env;
    this.stsEndpointOverride = stsEndpointOverride;
    this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
  }

  @Override
  public AwsCredentials resolveOrNull() {
    if (!env.has("AWS_ROLE_ARN") || !env.has("AWS_WEB_IDENTITY_TOKEN_FILE")) {
      return null;
    }
    String roleArn = env.get("AWS_ROLE_ARN");
    String tokenFile = env.get("AWS_WEB_IDENTITY_TOKEN_FILE");

    String token;
    try {
      token = env.readFile(tokenFile);
    } catch (IOException e) {
      throw new KmsException(
          "AWS_ROLE_ARN is set but the web identity token at "
              + tokenFile
              + " is unreadable —"
              + " the service account may be missing its projected token volume",
          e);
    }

    String sessionName = env.get("AWS_ROLE_SESSION_NAME", "keycloak-kms");
    String region = env.get("AWS_REGION", env.get("AWS_DEFAULT_REGION", "us-east-1"));
    String endpoint =
        stsEndpointOverride != null && !stsEndpointOverride.isBlank()
            ? stsEndpointOverride
            : "https://sts." + region + ".amazonaws.com";

    String form =
        "Action=AssumeRoleWithWebIdentity"
            + "&Version=2011-06-15"
            + "&RoleArn="
            + enc(roleArn)
            + "&RoleSessionName="
            + enc(sessionName)
            + "&WebIdentityToken="
            + enc(token);

    try {
      HttpResponse<String> r =
          http.send(
              HttpRequest.newBuilder(URI.create(endpoint))
                  .timeout(Duration.ofSeconds(5))
                  .header("Content-Type", "application/x-www-form-urlencoded")
                  .header("Accept", "application/xml")
                  .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      if (r.statusCode() / 100 != 2) {
        throw new KmsException(
            "STS AssumeRoleWithWebIdentity for "
                + roleArn
                + " returned HTTP "
                + r.statusCode()
                + ": "
                + r.body()
                + " — check the role's trust policy names this cluster's OIDC provider and this"
                + " service account");
      }
      return StsCredentialsXml.parse(r.body(), name());
    } catch (IOException e) {
      throw new KmsException("could not reach STS at " + endpoint, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new KmsException("interrupted calling STS", e);
    }
  }

  private static String enc(String v) {
    return URLEncoder.encode(v, StandardCharsets.UTF_8);
  }

  @Override
  public String name() {
    return "web-identity";
  }
}
