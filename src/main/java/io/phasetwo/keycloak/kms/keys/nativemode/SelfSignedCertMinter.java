package io.phasetwo.keycloak.kms.keys.nativemode;

import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsSigningAlgorithm;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

/**
 * Mints a self-signed certificate for a key whose private half cannot be extracted.
 *
 * <p>Keycloak's RSA key providers carry an X.509 certificate, and SAML descriptor endpoints and
 * some client-authentication flows read it. A non-extractable key cannot be handed to the usual
 * certificate generator — but a certificate does not need the private key in hand, only a signature
 * over the to-be-signed structure. So the TBS bytes go to {@code kms:Sign} like anything else.
 *
 * <p>Done <strong>once</strong>, when the provider is created. The result is public material and is
 * stored in component config in the clear, exactly as stock stores it.
 */
public final class SelfSignedCertMinter {

  /**
   * Ten years. A self-signed realm certificate is an identifier, not a trust anchor — nothing
   * validates its chain — and an expiry that arrives unnoticed would break SAML metadata for no
   * benefit. Stock Keycloak takes the same view.
   */
  private static final int VALIDITY_YEARS = 10;

  private SelfSignedCertMinter() {}

  public static X509Certificate mint(
      KmsProvider kms,
      String keyId,
      PublicKey publicKey,
      String subject,
      KmsSigningAlgorithm algorithm) {
    try {
      X500Name name = new X500Name("CN=" + subject);
      Instant now = Instant.now();
      JcaX509v3CertificateBuilder builder =
          new JcaX509v3CertificateBuilder(
              name,
              new BigInteger(64, new SecureRandom()),
              Date.from(now),
              Date.from(now.plus(365L * VALIDITY_YEARS, ChronoUnit.DAYS)),
              name,
              publicKey);

      X509CertificateHolder holder =
          builder.build(new KmsContentSigner(kms, keyId, certificateAlgorithm(algorithm)));
      return new JcaX509CertificateConverter().getCertificate(holder);
    } catch (KmsException e) {
      throw e;
    } catch (Exception e) {
      throw new KmsException(
          "could not mint a self-signed certificate for KMS key " + keyId + ": " + e.getMessage(),
          e);
    }
  }

  /**
   * The algorithm to sign the certificate with.
   *
   * <p>Always PKCS#1 for RSA, even when the realm key signs tokens with PSS. A PSS certificate
   * signature needs explicit RSASSA-PSS parameters in the AlgorithmIdentifier, and they add nothing
   * to a self-signed identifier whose chain nobody validates. The important part is that the
   * declared algorithm and the algorithm actually used are the same one — declaring PKCS#1 while
   * signing PSS produces a certificate that cannot be verified by anything.
   */
  static KmsSigningAlgorithm certificateAlgorithm(KmsSigningAlgorithm algorithm) {
    return switch (algorithm) {
      case RSASSA_PSS_SHA_256 -> KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_256;
      case RSASSA_PSS_SHA_384 -> KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_384;
      case RSASSA_PSS_SHA_512 -> KmsSigningAlgorithm.RSASSA_PKCS1_V1_5_SHA_512;
      default -> algorithm;
    };
  }

  /** A BouncyCastle {@link ContentSigner} whose signature comes from the KMS. */
  private static final class KmsContentSigner implements ContentSigner {

    private final KmsProvider kms;
    private final String keyId;
    private final KmsSigningAlgorithm algorithm;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final AlgorithmIdentifier algorithmIdentifier;

    KmsContentSigner(KmsProvider kms, String keyId, KmsSigningAlgorithm algorithm) {
      this.kms = kms;
      this.keyId = keyId;
      this.algorithm = algorithm;
      this.algorithmIdentifier =
          new DefaultSignatureAlgorithmIdentifierFinder().find(jcaName(algorithm));
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithmIdentifier;
    }

    @Override
    public OutputStream getOutputStream() {
      return buffer;
    }

    @Override
    public byte[] getSignature() {
      try {
        byte[] digest =
            MessageDigest.getInstance(algorithm.digestAlgorithm()).digest(buffer.toByteArray());
        return kms.sign(keyId, algorithm, digest);
      } catch (java.security.NoSuchAlgorithmException e) {
        throw new KmsException("no " + algorithm.digestAlgorithm() + " available", e);
      }
    }

    /** The name BouncyCastle's algorithm finder expects. */
    private static String jcaName(KmsSigningAlgorithm algorithm) {
      return switch (algorithm) {
        case ECDSA_SHA_256 -> "SHA256withECDSA";
        case ECDSA_SHA_384 -> "SHA384withECDSA";
        case ECDSA_SHA_512 -> "SHA512withECDSA";
        case RSASSA_PKCS1_V1_5_SHA_256 -> "SHA256withRSA";
        case RSASSA_PKCS1_V1_5_SHA_384 -> "SHA384withRSA";
        case RSASSA_PKCS1_V1_5_SHA_512 -> "SHA512withRSA";
        // Unreachable: certificateAlgorithm() has already mapped PSS to its PKCS#1 equivalent.
        case RSASSA_PSS_SHA_256, RSASSA_PSS_SHA_384, RSASSA_PSS_SHA_512 ->
            throw new IllegalStateException("PSS should have been mapped to PKCS#1: " + algorithm);
      };
    }
  }
}
