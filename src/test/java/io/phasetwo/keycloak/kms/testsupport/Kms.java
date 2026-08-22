package io.phasetwo.keycloak.kms.testsupport;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.phasetwo.keycloak.kms.aws.AwsCredentials;
import io.phasetwo.keycloak.kms.aws.AwsSigV4Signer;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;

/**
 * Provisions KMS keys for tests.
 *
 * <p>{@code CreateKey} is deliberately absent from the extension itself — bring-your-own-key is a
 * design decision, not an omission — so tests that need a key make one here rather than growing the
 * production surface to be convenient. The request is signed with the production {@link
 * AwsSigV4Signer}, so this is not a second implementation of anything that matters.
 */
public final class Kms {

  private Kms() {}

  public static String createKey(
      URI endpoint, String region, String accessKey, String secretKey, String usage, String spec) {
    String payload = "{\"KeyUsage\":\"" + usage + "\",\"KeySpec\":\"" + spec + "\"}";
    String host =
        endpoint.getPort() > 0 ? endpoint.getHost() + ":" + endpoint.getPort() : endpoint.getHost();

    Map<String, String> headers =
        AwsSigV4Signer.sign(
            AwsCredentials.longLived(accessKey, secretKey, "test"),
            region,
            "kms",
            host,
            "/",
            Map.of(
                "Content-Type", "application/x-amz-json-1.1",
                "X-Amz-Target", "TrentService.CreateKey"),
            payload,
            ZonedDateTime.now(ZoneOffset.UTC));

    HttpRequest.Builder request =
        HttpRequest.newBuilder(endpoint).POST(HttpRequest.BodyPublishers.ofString(payload));
    headers.forEach(
        (k, v) -> {
          if (!"host".equalsIgnoreCase(k)) {
            request.header(k, v);
          }
        });

    try {
      HttpResponse<String> response =
          HttpClient.newHttpClient().send(request.build(), HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() / 100 != 2) {
        throw new IllegalStateException("CreateKey failed: " + response.body());
      }
      return new ObjectMapper().readTree(response.body()).get("KeyMetadata").get("KeyId").asText();
    } catch (IOException e) {
      throw new IllegalStateException("could not create a test key", e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException(e);
    }
  }
}
