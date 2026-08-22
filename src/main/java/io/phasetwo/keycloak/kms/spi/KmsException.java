package io.phasetwo.keycloak.kms.spi;

/**
 * A KMS operation failed.
 *
 * <p>{@link #isRetryable()} separates the transient failures (throttling, 5xx, a socket that died)
 * from the terminal ones (access denied, key disabled, ciphertext that does not belong to this
 * key). Callers on the token path must not retry the terminal ones, and operators must not be told
 * to check their network when the real answer is an IAM policy.
 */
public class KmsException extends RuntimeException {

  private final boolean retryable;

  public KmsException(String message) {
    this(message, null, false);
  }

  public KmsException(String message, Throwable cause) {
    this(message, cause, false);
  }

  public KmsException(String message, Throwable cause, boolean retryable) {
    super(message, cause);
    this.retryable = retryable;
  }

  public boolean isRetryable() {
    return retryable;
  }

  public static KmsException retryable(String message, Throwable cause) {
    return new KmsException(message, cause, true);
  }
}
