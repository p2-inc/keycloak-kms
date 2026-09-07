package io.phasetwo.keycloak.kms.keys;

import java.util.Base64;

/**
 * The {@code kms://v1/<base64url>} value that stands in for key material in component config.
 *
 * <p>The version segment is the point: a future change to what the ciphertext contains is then a
 * legible "unsupported version" error rather than a decrypt failure that looks like a corrupted key
 * or a wrong CMK.
 *
 * <p>Self-contained by design. The alternative — a reference to a blob held in a separate key store
 * — needs a store, an RPC and a consistency story to hold something that fits in a config row.
 */
public final class WrappedMaterial {

  public static final String SCHEME = "kms://";
  public static final String V1 = SCHEME + "v1/";

  private WrappedMaterial() {}

  /** Encode raw KMS ciphertext as a config value. */
  public static String encode(byte[] ciphertext) {
    return V1 + Base64.getUrlEncoder().withoutPadding().encodeToString(ciphertext);
  }

  /**
   * Decode a config value back to raw KMS ciphertext.
   *
   * @throws IllegalArgumentException if the value is absent, not a {@code kms://} value, or a
   *     version this build does not know
   */
  public static byte[] decode(String value) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException("no wrapped material present");
    }
    if (!value.startsWith(SCHEME)) {
      throw new IllegalArgumentException(
          "not a kms:// wrapped value — refusing to treat it as key material");
    }
    if (!value.startsWith(V1)) {
      throw new IllegalArgumentException(
          "unsupported wrapped-material version: " + versionOf(value) + " (this build reads v1)");
    }
    return Base64.getUrlDecoder().decode(value.substring(V1.length()));
  }

  /** Whether a config value looks like wrapped material at all. */
  public static boolean isWrapped(String value) {
    return value != null && value.startsWith(SCHEME);
  }

  private static String versionOf(String value) {
    int slash = value.indexOf('/', SCHEME.length());
    return slash < 0 ? "<malformed>" : value.substring(SCHEME.length(), slash);
  }
}
