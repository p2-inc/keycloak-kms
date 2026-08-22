package io.phasetwo.keycloak.kms.aws;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * AWS Signature Version 4 for JSON POST requests.
 *
 * <p>Descended from the SES signer in {@code keycloak-transactional-email}, generalised so the
 * service and the header set are inputs rather than constants, and extended with the session-token
 * header that temporary credentials require — IRSA, EKS Pod Identity, ECS task roles and instance
 * profiles all issue temporary credentials, so without {@code x-amz-security-token} this extension
 * would only work with long-lived access keys, which is precisely the thing it exists to avoid.
 *
 * <p>Correctness here is not self-evident, so {@code AwsSigV4SignerTest} checks the output against
 * signatures produced by botocore — an independent implementation — rather than against our own
 * expectations.
 */
public final class AwsSigV4Signer {

  private static final String ALGORITHM = "AWS4-HMAC-SHA256";
  private static final DateTimeFormatter DATE_TIME_FMT =
      DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").withZone(ZoneOffset.UTC);
  private static final DateTimeFormatter DATE_FMT =
      DateTimeFormatter.ofPattern("yyyyMMdd").withZone(ZoneOffset.UTC);

  private AwsSigV4Signer() {}

  /**
   * Sign a request and return the headers to send.
   *
   * <p>The returned map contains every header that was signed plus {@code Authorization}. Callers
   * must send exactly these — adding a header afterwards is fine, but changing a signed one
   * invalidates the signature.
   *
   * @param credentials access key, secret and (optionally) session token
   * @param region e.g. {@code us-east-1}
   * @param service e.g. {@code kms}
   * @param host the request host, which is also the signed {@code host} header
   * @param path the canonical URI, {@code /} for KMS
   * @param headers headers to sign besides {@code host}, {@code x-amz-date} and the session token
   * @param payload the request body
   * @param now the signing timestamp
   */
  public static Map<String, String> sign(
      AwsCredentials credentials,
      String region,
      String service,
      String host,
      String path,
      Map<String, String> headers,
      String payload,
      ZonedDateTime now) {

    String dateTime = DATE_TIME_FMT.format(now);
    String date = DATE_FMT.format(now);

    // Header names are matched case-insensitively and emitted lowercase, per the spec.
    TreeMap<String, String> signed = new TreeMap<>();
    headers.forEach((k, v) -> signed.put(k.toLowerCase(Locale.ROOT), v.trim()));
    signed.put("host", host);
    signed.put("x-amz-date", dateTime);
    if (credentials.sessionToken() != null && !credentials.sessionToken().isBlank()) {
      signed.put("x-amz-security-token", credentials.sessionToken());
    }

    StringBuilder canonicalHeaders = new StringBuilder();
    signed.forEach((k, v) -> canonicalHeaders.append(k).append(':').append(v).append('\n'));
    String signedHeaders = String.join(";", signed.keySet());

    String payloadHash = sha256Hex(payload);
    String canonicalRequest =
        "POST\n"
            + path
            + "\n"
            + ""
            + "\n"
            + canonicalHeaders
            + "\n"
            + signedHeaders
            + "\n"
            + payloadHash;

    String credentialScope = date + "/" + region + "/" + service + "/aws4_request";
    String stringToSign =
        ALGORITHM + "\n" + dateTime + "\n" + credentialScope + "\n" + sha256Hex(canonicalRequest);

    byte[] signingKey =
        hmac(
            hmac(
                hmac(
                    hmac(
                        ("AWS4" + credentials.secretAccessKey()).getBytes(StandardCharsets.UTF_8),
                        date),
                    region),
                service),
            "aws4_request");

    String signature = hex(hmac(signingKey, stringToSign));

    String authorization =
        ALGORITHM
            + " Credential="
            + credentials.accessKeyId()
            + "/"
            + credentialScope
            + ", SignedHeaders="
            + signedHeaders
            + ", Signature="
            + signature;

    // Return what to actually send: the signed headers, plus Authorization.
    Map<String, String> out = new TreeMap<>(signed);
    out.put("Authorization", authorization);
    return out;
  }

  static String sha256Hex(String value) {
    try {
      return hex(
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }

  private static byte[] hmac(byte[] key, String data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException("HMAC-SHA256 failed", e);
    }
  }

  private static String hex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
    }
    return sb.toString();
  }
}
