package io.phasetwo.keycloak.kms.keys.nativemode;

import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * A {@link SignatureSpi} that signs through a KMS.
 *
 * <p>Buffers what {@code update()} is given, hashes it locally at {@code sign()} time, and sends
 * only the digest. Hashing locally rather than shipping the message is what keeps the request small
 * and keeps the choice of hash out of the KMS's hands.
 *
 * <p>Verification is not implemented. Keycloak verifies with the public key through the ordinary
 * providers, which is both faster and free; routing verification through the KMS would add an API
 * call and a quota consumer to every token validation for no security gain, since a public key is
 * public.
 */
public abstract class KmsSignatureSpi extends SignatureSpi {

  private final KmsSigningAlgorithm algorithm;
  private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(512);
  private KmsPrivateKey key;

  protected KmsSignatureSpi(KmsSigningAlgorithm algorithm) {
    this.algorithm = algorithm;
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (!(privateKey instanceof KmsPrivateKey kmsKey)) {
      // Not ours. Throwing here is what makes JCA move on to the next provider, so this is the
      // path every ordinary key in the server takes through this class — it must stay cheap and
      // must never do anything but decline.
      throw new InvalidKeyException("not a KMS-held key");
    }
    this.key = kmsKey;
    buffer.reset();
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    throw new InvalidKeyException(
        "keycloak-kms does not verify through the KMS; verification uses the public key directly");
  }

  @Override
  protected void engineUpdate(byte b) {
    buffer.write(b);
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) {
    buffer.write(b, off, len);
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (key == null) {
      throw new SignatureException("not initialised for signing");
    }
    try {
      byte[] digest =
          MessageDigest.getInstance(algorithm.digestAlgorithm()).digest(buffer.toByteArray());
      buffer.reset();
      return key.kms().sign(key.keyId(), algorithm, digest);
    } catch (NoSuchAlgorithmException e) {
      throw new SignatureException("no " + algorithm.digestAlgorithm() + " available", e);
    } catch (KmsException e) {
      throw new SignatureException(
          "KMS refused to sign with " + key.keyId() + ": " + e.getMessage(), e);
    }
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    throw new SignatureException("verification is not routed through the KMS");
  }

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
    if (params == null) {
      return;
    }
    if (params instanceof PSSParameterSpec pss) {
      // Keycloak sets PSS parameters after initSign. KMS's RSASSA_PSS_* algorithms fix the salt
      // length to the digest length and MGF1 to the same hash, so anything else would produce a
      // signature the verifier rejects — better to refuse than to sign something wrong.
      requirePssMatches(pss);
      return;
    }
    throw new InvalidAlgorithmParameterException("unsupported parameters: " + params.getClass());
  }

  private void requirePssMatches(PSSParameterSpec pss) throws InvalidAlgorithmParameterException {
    String expectedHash = algorithm.digestAlgorithm();
    int expectedSaltLength =
        switch (expectedHash) {
          case "SHA-256" -> 32;
          case "SHA-384" -> 48;
          default -> 64;
        };
    if (!expectedHash.equals(pss.getDigestAlgorithm())) {
      throw new InvalidAlgorithmParameterException(
          "PSS digest " + pss.getDigestAlgorithm() + " does not match " + algorithm);
    }
    if (pss.getSaltLength() != expectedSaltLength) {
      throw new InvalidAlgorithmParameterException(
          "AWS KMS fixes the PSS salt length to the digest length ("
              + expectedSaltLength
              + " bytes); "
              + pss.getSaltLength()
              + " was requested");
    }
    if (pss.getMGFParameters() instanceof MGF1ParameterSpec mgf1
        && !expectedHash.equals(mgf1.getDigestAlgorithm())) {
      throw new InvalidAlgorithmParameterException(
          "AWS KMS fixes MGF1 to the signing digest; "
              + mgf1.getDigestAlgorithm()
              + " was requested");
    }
  }

  @Override
  @Deprecated
  protected void engineSetParameter(String param, Object value) {
    throw new UnsupportedOperationException("deprecated parameter API is not supported");
  }

  @Override
  @Deprecated
  protected Object engineGetParameter(String param) {
    throw new UnsupportedOperationException("deprecated parameter API is not supported");
  }

  // One concrete class per algorithm, because a JCA Provider maps an algorithm name to a class.

  public static final class EcdsaSha256 extends KmsSignatureSpi {
    public EcdsaSha256() {
      super(KmsSigningAlgorithm.ECDSA_SHA_256);
    }
  }

  public static final class EcdsaSha384 extends KmsSignatureSpi {
    public EcdsaSha384() {
      super(KmsSigningAlgorithm.ECDSA_SHA_384);
    }
  }

  public static final class EcdsaSha512 extends KmsSignatureSpi {
    public EcdsaSha512() {
      super(KmsSigningAlgorithm.ECDSA_SHA_512);
    }
  }

  public static final class RsaSha256 extends KmsSignatureSpi {
    public RsaSha256() {
      super(KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256);
    }
  }

  public static final class RsaSha384 extends KmsSignatureSpi {
    public RsaSha384() {
      super(KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_384);
    }
  }

  public static final class RsaSha512 extends KmsSignatureSpi {
    public RsaSha512() {
      super(KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_512);
    }
  }

  /**
   * PSS, which JCA exposes as a single {@code RSASSA-PSS} algorithm parameterised at runtime.
   *
   * <p>Defaults to SHA-256 and re-targets itself when {@code setParameter} names a different digest
   * — which is how Keycloak drives PS384 and PS512 through the same {@code Signature} instance.
   */
  public static final class RsaPss extends SignatureSpi {

    private KmsSignatureSpi delegate =
        new KmsSignatureSpi(KmsSigningAlgorithm.RSASSA_PSS_SHA_256) {};

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
      delegate.engineInitSign(privateKey);
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
      throw new InvalidKeyException("keycloak-kms does not verify through the KMS");
    }

    @Override
    protected void engineUpdate(byte b) {
      delegate.engineUpdate(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) {
      delegate.engineUpdate(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
      return delegate.engineSign();
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
      throw new SignatureException("verification is not routed through the KMS");
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params)
        throws InvalidAlgorithmParameterException {
      if (params instanceof PSSParameterSpec pss) {
        KmsSigningAlgorithm target =
            switch (pss.getDigestAlgorithm()) {
              case "SHA-256" -> KmsSigningAlgorithm.RSASSA_PSS_SHA_256;
              case "SHA-384" -> KmsSigningAlgorithm.RSASSA_PSS_SHA_384;
              case "SHA-512" -> KmsSigningAlgorithm.RSASSA_PSS_SHA_512;
              default ->
                  throw new InvalidAlgorithmParameterException(
                      "AWS KMS has no PSS variant for " + pss.getDigestAlgorithm());
            };
        // Re-point at the right algorithm, keeping whatever key was already installed.
        KmsSignatureSpi retargeted = new KmsSignatureSpi(target) {};
        try {
          if (delegate.key != null) {
            retargeted.engineInitSign(delegate.key);
          }
        } catch (InvalidKeyException e) {
          // Unreachable: the key came from our own engineInitSign, so it is a KmsPrivateKey.
          throw new InvalidAlgorithmParameterException("could not carry the key across", e);
        }
        retargeted.engineSetParameter(pss);
        delegate = retargeted;
        return;
      }
      delegate.engineSetParameter(params);
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String param, Object value) {
      throw new UnsupportedOperationException("deprecated parameter API is not supported");
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String param) {
      throw new UnsupportedOperationException("deprecated parameter API is not supported");
    }
  }
}
