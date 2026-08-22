package io.phasetwo.keycloak.kms.testsupport;

import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsKeyDescription;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Wraps a {@link KmsProvider} and counts what it is asked to do.
 *
 * <p>Call counts are the only way to assert the things that matter most about the caching layer:
 * that a warm key does not touch the KMS, and that a disabled provider does not either.
 */
public class CountingKms implements KmsProvider {

  private final KmsProvider delegate;
  public final AtomicInteger encrypts = new AtomicInteger();
  public final AtomicInteger decrypts = new AtomicInteger();
  public final AtomicInteger signs = new AtomicInteger();
  public final List<EncryptionContext> decryptContexts = new ArrayList<>();

  /** When set, decrypt returns this instead of the real plaintext. */
  public byte[] corruptDecryptTo;

  public CountingKms(KmsProvider delegate) {
    this.delegate = delegate;
  }

  public void reset() {
    encrypts.set(0);
    decrypts.set(0);
    signs.set(0);
    decryptContexts.clear();
  }

  @Override
  public byte[] encrypt(String keyId, byte[] plaintext, EncryptionContext context) {
    encrypts.incrementAndGet();
    return delegate.encrypt(keyId, plaintext, context);
  }

  @Override
  public byte[] decrypt(String keyId, byte[] ciphertext, EncryptionContext context) {
    decrypts.incrementAndGet();
    decryptContexts.add(context);
    byte[] real = delegate.decrypt(keyId, ciphertext, context);
    return corruptDecryptTo != null ? corruptDecryptTo : real;
  }

  @Override
  public boolean supportsNativeKeys() {
    return delegate.supportsNativeKeys();
  }

  @Override
  public byte[] sign(String keyId, KmsSigningAlgorithm algorithm, byte[] digest) {
    signs.incrementAndGet();
    return delegate.sign(keyId, algorithm, digest);
  }

  @Override
  public PublicKey publicKey(String keyId) {
    return delegate.publicKey(keyId);
  }

  @Override
  public KmsKeyDescription describe(String keyId) {
    return delegate.describe(keyId);
  }

  @Override
  public String defaultKeyId() {
    return delegate.defaultKeyId();
  }
}
