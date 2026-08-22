package io.phasetwo.keycloak.kms.aws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import lombok.extern.jbosslog.JBossLog;

/**
 * The AWS KMS wire protocol, over JDK {@link HttpClient}.
 *
 * <p>KMS speaks {@code application/x-amz-json-1.1}: a POST to {@code /} with the operation in the
 * {@code X-Amz-Target} header. Six operations are enough for everything this extension does, which
 * is why there is no AWS SDK here — the SDK would add several megabytes to {@code providers/} and a
 * Jackson version to argue with, to save perhaps two hundred lines.
 */
@JBossLog
public class KmsApi {

  private static final String CONTENT_TYPE = "application/x-amz-json-1.1";
  private static final String SERVICE = "kms";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  /**
   * Failures worth trying again. Everything else — {@code AccessDeniedException}, {@code
   * DisabledException}, {@code InvalidCiphertextException}, {@code NotFoundException} — is a
   * standing condition, and retrying it just delays a clear error behind three timeouts.
   */
  private static final Set<String> RETRYABLE =
      Set.of(
          "ThrottlingException",
          "KMSInternalException",
          "LimitExceededException",
          "DependencyTimeoutException",
          "InternalFailure",
          "ServiceUnavailable",
          "RequestTimeout");

  private static final int MAX_ATTEMPTS = 3;

  private final HttpClient http;
  private final AwsCredentialsProvider credentials;
  private final String region;
  private final URI endpoint;
  private final String host;

  public KmsApi(AwsCredentialsProvider credentials, String region, String endpointOverride) {
    this.credentials = credentials;
    this.region = region;
    this.endpoint =
        URI.create(
            endpointOverride != null && !endpointOverride.isBlank()
                ? endpointOverride
                : "https://kms." + region + ".amazonaws.com");
    this.host =
        endpoint.getPort() > 0 ? endpoint.getHost() + ":" + endpoint.getPort() : endpoint.getHost();
    this.http =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
  }

  // ---------------------------------------------------------------- operations

  public byte[] encrypt(String keyId, byte[] plaintext, EncryptionContext context) {
    ObjectNode req = MAPPER.createObjectNode();
    req.put("KeyId", keyId);
    req.put("Plaintext", Base64.getEncoder().encodeToString(plaintext));
    putContext(req, context);
    return b64(call("Encrypt", req).get("CiphertextBlob"), "CiphertextBlob");
  }

  public byte[] decrypt(String keyId, byte[] ciphertext, EncryptionContext context) {
    ObjectNode req = MAPPER.createObjectNode();
    // Naming the key is not redundant even though the ciphertext carries it: it stops a ciphertext
    // sealed under some other key in the account from being decrypted here by accident.
    if (keyId != null) {
      req.put("KeyId", keyId);
    }
    req.put("CiphertextBlob", Base64.getEncoder().encodeToString(ciphertext));
    putContext(req, context);
    return b64(call("Decrypt", req).get("Plaintext"), "Plaintext");
  }

  public KmsKeyDescription describeKey(String keyId) {
    ObjectNode req = MAPPER.createObjectNode();
    req.put("KeyId", keyId);
    JsonNode md = call("DescribeKey", req).get("KeyMetadata");
    if (md == null) {
      throw new KmsException("DescribeKey returned no KeyMetadata for " + keyId);
    }
    // KeySpec superseded CustomerMasterKeySpec; older endpoints and some emulators send only the
    // latter, so read whichever is present rather than assuming.
    String spec = text(md, "KeySpec", text(md, "CustomerMasterKeySpec", null));
    return new KmsKeyDescription(
        text(md, "Arn", text(md, "KeyId", keyId)),
        spec,
        text(md, "KeyUsage", null),
        md.path("Enabled").asBoolean(false));
  }

  public byte[] sign(String keyId, KmsSigningAlgorithm algorithm, byte[] digest) {
    ObjectNode req = MAPPER.createObjectNode();
    req.put("KeyId", keyId);
    req.put("Message", Base64.getEncoder().encodeToString(digest));
    // Always DIGEST. The 4 KB RAW limit would be enough for a JWT today, but hashing locally keeps
    // one round trip's worth of data off the wire and keeps the hash under our control.
    req.put("MessageType", "DIGEST");
    req.put("SigningAlgorithm", algorithm.name());
    return b64(call("Sign", req).get("Signature"), "Signature");
  }

  /** Returns the DER SubjectPublicKeyInfo. */
  public byte[] getPublicKey(String keyId) {
    ObjectNode req = MAPPER.createObjectNode();
    req.put("KeyId", keyId);
    return b64(call("GetPublicKey", req).get("PublicKey"), "PublicKey");
  }

  // ---------------------------------------------------------------- transport

  private static void putContext(ObjectNode req, EncryptionContext context) {
    if (context == null || context.asMap().isEmpty()) {
      return;
    }
    ObjectNode ec = req.putObject("EncryptionContext");
    context.asMap().forEach(ec::put);
  }

  private JsonNode call(String operation, ObjectNode body) {
    String payload;
    try {
      payload = MAPPER.writeValueAsString(body);
    } catch (IOException e) {
      throw new KmsException("could not serialise a " + operation + " request", e);
    }

    KmsException last = null;
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        return send(operation, payload);
      } catch (KmsException e) {
        last = e;
        if (!e.isRetryable() || attempt == MAX_ATTEMPTS) {
          throw e;
        }
        long backoffMs = (long) (Math.pow(2, attempt - 1) * 100);
        log.debugf(
            "KMS %s failed (attempt %d/%d, retrying in %dms): %s",
            operation, attempt, MAX_ATTEMPTS, backoffMs, e.getMessage());
        try {
          Thread.sleep(backoffMs);
        } catch (InterruptedException ie) {
          Thread.currentThread().interrupt();
          throw new KmsException("interrupted while retrying KMS " + operation, ie);
        }
      }
    }
    throw last;
  }

  private JsonNode send(String operation, String payload) {
    AwsCredentials creds = credentials.resolve();
    Map<String, String> headers =
        AwsSigV4Signer.sign(
            creds,
            region,
            SERVICE,
            host,
            "/",
            Map.of("Content-Type", CONTENT_TYPE, "X-Amz-Target", "TrentService." + operation),
            payload,
            ZonedDateTime.now(ZoneOffset.UTC));

    HttpRequest.Builder b =
        HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofSeconds(10))
            .POST(HttpRequest.BodyPublishers.ofString(payload, StandardCharsets.UTF_8));
    headers.forEach(
        (k, v) -> {
          // 'host' is set by the client from the URI and rejected as a user header.
          if (!"host".equalsIgnoreCase(k)) {
            b.header(k, v);
          }
        });

    HttpResponse<String> response;
    try {
      response = http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw KmsException.retryable("KMS " + operation + " could not reach " + endpoint, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new KmsException("interrupted calling KMS " + operation, e);
    }

    if (response.statusCode() / 100 == 2) {
      try {
        return MAPPER.readTree(response.body());
      } catch (IOException e) {
        throw new KmsException("KMS " + operation + " returned a body that is not JSON", e);
      }
    }
    throw errorFor(operation, response);
  }

  /**
   * Turn a KMS error body into something an operator can act on.
   *
   * <p>KMS reports the error type in a {@code __type} field which is sometimes bare and sometimes
   * prefixed with a namespace. Getting this parsing wrong would mean every error looked
   * non-retryable, which is survivable, or every error looked retryable, which is not — a
   * throttling backoff around {@code AccessDeniedException} turns a clear IAM problem into a slow
   * one.
   */
  private KmsException errorFor(String operation, HttpResponse<String> response) {
    String type = "HTTP " + response.statusCode();
    String message = response.body();
    try {
      JsonNode err = MAPPER.readTree(response.body());
      String raw = text(err, "__type", null);
      if (raw != null) {
        type = raw.contains("#") ? raw.substring(raw.indexOf('#') + 1) : raw;
      }
      String m = text(err, "message", text(err, "Message", null));
      if (m != null) {
        message = m;
      }
    } catch (IOException ignored) {
      // Not JSON — keep the raw body, which is more useful than a parse complaint.
    }

    boolean retryable = RETRYABLE.contains(type) || response.statusCode() >= 500;
    String hint = hintFor(type);
    return new KmsException(
        "KMS "
            + operation
            + " failed: "
            + type
            + " — "
            + message
            + (hint == null ? "" : " " + hint),
        null,
        retryable);
  }

  /** Where the error alone does not say what to do, say it. */
  private static String hintFor(String type) {
    return switch (type) {
      case "AccessDeniedException" ->
          "Check the IAM policy attached to this server's role: envelope"
              + " mode needs kms:Encrypt, kms:Decrypt and kms:DescribeKey; native mode needs kms:Sign"
              + " and kms:GetPublicKey. If the key policy has an EncryptionContext condition, confirm"
              + " it matches 'app=keycloak'.";
      case "IncorrectKeyException", "InvalidCiphertextException" ->
          "This ciphertext was not"
              + " produced by this key with this encryption context. If a realm was restored from"
              + " another environment's database, its wrapped material belongs to that environment's"
              + " CMK.";
      case "DisabledException", "KMSInvalidStateException" ->
          "The key exists but is disabled or"
              + " pending deletion. Realms depending on it cannot serve tokens until it is re-enabled.";
      case "NotFoundException" ->
          "No such key in this region. Check --spi-kms--aws--key-id and"
              + " --spi-kms--aws--region; a multi-Region key must have a replica in this region.";
      case "ThrottlingException" ->
          "KMS request rate exceeded. For native mode this is the"
              + " asymmetric operation quota, which is shared account-wide and is the ceiling on how"
              + " fast this cluster can issue tokens.";
      default -> null;
    };
  }

  private static byte[] b64(JsonNode node, String field) {
    if (node == null || node.isNull()) {
      throw new KmsException("KMS response is missing " + field);
    }
    return Base64.getDecoder().decode(node.asText());
  }

  private static String text(JsonNode node, String field, String fallback) {
    JsonNode v = node.get(field);
    return v == null || v.isNull() ? fallback : v.asText();
  }
}
