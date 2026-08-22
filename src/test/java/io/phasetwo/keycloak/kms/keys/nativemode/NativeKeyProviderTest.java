package io.phasetwo.keycloak.kms.keys.nativemode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.keys.KmsAttributes;
import io.phasetwo.keycloak.kms.local.LocalKmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.testsupport.CountingKms;
import io.phasetwo.keycloak.kms.testsupport.Crypto;
import io.phasetwo.keycloak.kms.testsupport.FakeRealm;
import io.phasetwo.keycloak.kms.testsupport.FakeSession;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;

/**
 * Native mode, against the local backend's deterministic keypairs.
 *
 * <p>The load-bearing tests here are the two that have nothing to do with KMS: that Keycloak's own
 * signing path reaches our JCA provider for a KMS-held key, and that it does <em>not</em> for any
 * ordinary key. Native mode works by inserting itself into a global JCA lookup, and the failure
 * mode nobody would notice in a happy-path test is quietly changing how every other key in the
 * server gets signed.
 */
class NativeKeyProviderTest {

  private static final byte[] KEK =
      "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
  private static final String EC_KEY = "ec256:realm-signing";
  private static final String RSA_KEY = "rsa2048:realm-signing";

  private CountingKms kms;
  private FakeRealm realm;
  private KeycloakSession session;

  @BeforeAll
  static void bootCrypto() {
    Crypto.init();
    KmsJcaProvider.register();
  }

  @BeforeEach
  void setUp() {
    kms = new CountingKms(new LocalKmsProvider(KEK, "default"));
    realm = new FakeRealm("realm-id", "customer-b");
    session = FakeSession.session(kms, realm.model());
    realm.setSession(session);
  }

  private ComponentModel component(String providerId, String kmsKeyId) {
    ComponentModel model = new ComponentModel();
    model.setId("component-" + providerId);
    model.setParentId("realm-id");
    model.setProviderId(providerId);
    model.setProviderType(KeyProvider.class.getName());
    model.setConfig(new MultivaluedHashMap<>());
    model.put(Attributes.PRIORITY_KEY, 100L);
    if (kmsKeyId != null) {
      model.put(KmsAttributes.KMS_KEY_ID, kmsKeyId);
    }
    return model;
  }

  private static KeyWrapper only(KeyProvider provider) {
    List<KeyWrapper> keys = provider.getKeysStream().toList();
    assertEquals(1, keys.size());
    return keys.get(0);
  }

  // ------------------------------------------------------------------ the JCA seam

  @Test
  @DisplayName("Keycloak's signing path reaches the KMS for a native key, and the result verifies")
  void ecNativeSignsThroughKms() throws Exception {
    KmsEcNativeKeyProviderFactory factory = new KmsEcNativeKeyProviderFactory();
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, EC_KEY);
    factory.validateConfiguration(session, realm.model(), model);
    KeyWrapper key = only(factory.create(session, model));
    kms.reset();

    // Exactly what AsymmetricSignatureSignerContext does — no provider named, opaque key.
    byte[] message = "the token".getBytes(StandardCharsets.UTF_8);
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign((PrivateKey) key.getPrivateKey());
    signer.update(message);
    byte[] signature = signer.sign();

    assertEquals(
        KmsJcaProvider.NAME,
        signer.getProvider().getName(),
        "the JDK must select our provider for an opaque key");
    assertEquals(1, kms.signs.get(), "one token, one kms:Sign");

    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify((java.security.PublicKey) key.getPublicKey());
    verifier.update(message);
    assertTrue(verifier.verify(signature), "the KMS signature must verify against the public key");
  }

  @Test
  @DisplayName("an ordinary key is still signed by the JDK, never by us")
  void ordinaryKeysAreNotHijacked() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ordinary = generator.generateKeyPair();

    byte[] message = "an ordinary signature".getBytes(StandardCharsets.UTF_8);
    Signature signer = Signature.getInstance("SHA256withECDSA");
    signer.initSign(ordinary.getPrivate());
    signer.update(message);
    byte[] signature = signer.sign();

    assertFalse(
        KmsJcaProvider.NAME.equals(signer.getProvider().getName()),
        "registering our provider must not change how any other key in the server is signed");
    assertEquals(0, kms.signs.get());

    Signature verifier = Signature.getInstance("SHA256withECDSA");
    verifier.initVerify(ordinary.getPublic());
    verifier.update(message);
    assertTrue(verifier.verify(signature));
  }

  @Test
  @DisplayName("RSA and PSS both route through the KMS")
  void rsaAndPss() throws Exception {
    KmsRsaNativeKeyProviderFactory factory = new KmsRsaNativeKeyProviderFactory();
    ComponentModel model = component(KmsRsaNativeKeyProviderFactory.ID, RSA_KEY);
    factory.validateConfiguration(session, realm.model(), model);
    KeyWrapper key = only(factory.create(session, model));

    Signature pkcs1 = Signature.getInstance("SHA256withRSA");
    pkcs1.initSign((PrivateKey) key.getPrivateKey());
    pkcs1.update("x".getBytes(StandardCharsets.UTF_8));
    assertEquals(KmsJcaProvider.NAME, pkcs1.getProvider().getName());
    assertNotNull(pkcs1.sign());

    // The local backend cannot do PSS, so this proves the routing, not the signature. Producing a
    // real PSS signature is what the LocalStack integration test is for.
    Signature pss = Signature.getInstance("RSASSA-PSS");
    pss.initSign((PrivateKey) key.getPrivateKey());
    assertEquals(KmsJcaProvider.NAME, pss.getProvider().getName());
    pss.setParameter(
        new java.security.spec.PSSParameterSpec(
            "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 32, 1));
    pss.update("x".getBytes(StandardCharsets.UTF_8));
    assertThrows(java.security.SignatureException.class, pss::sign);
  }

  @Test
  @DisplayName("PSS parameters KMS cannot honour are refused rather than signed wrongly")
  void pssParametersAreValidated() throws Exception {
    KmsRsaNativeKeyProviderFactory factory = new KmsRsaNativeKeyProviderFactory();
    ComponentModel model = component(KmsRsaNativeKeyProviderFactory.ID, RSA_KEY);
    factory.validateConfiguration(session, realm.model(), model);
    KeyWrapper key = only(factory.create(session, model));

    Signature pss = Signature.getInstance("RSASSA-PSS");
    pss.initSign((PrivateKey) key.getPrivateKey());
    // AWS fixes the salt length to the digest length; 20 would produce a signature that verifiers
    // expecting the JOSE convention would reject.
    assertThrows(
        java.security.InvalidAlgorithmParameterException.class,
        () ->
            pss.setParameter(
                new java.security.spec.PSSParameterSpec(
                    "SHA-256", "MGF1", java.security.spec.MGF1ParameterSpec.SHA256, 20, 1)));
  }

  @Test
  @DisplayName("verification is never routed through the KMS")
  void verificationIsLocal() throws Exception {
    Signature s = Signature.getInstance("SHA256withECDSA", KmsJcaProvider.NAME);
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    assertThrows(
        java.security.InvalidKeyException.class,
        () -> s.initVerify(generator.generateKeyPair().getPublic()));
  }

  // ------------------------------------------------------------------ the provider

  @Test
  @DisplayName("the key is built from config, so JWKS costs no KMS call")
  void jwksIsFree() {
    KmsEcNativeKeyProviderFactory factory = new KmsEcNativeKeyProviderFactory();
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, EC_KEY);
    factory.validateConfiguration(session, realm.model(), model);
    kms.reset();

    KeyWrapper key = only(factory.create(session, model));
    assertNotNull(key.getPublicKey());
    assertEquals(0, kms.signs.get());
    assertEquals(KeyType.EC, key.getType());
    assertEquals(Algorithm.ES256, key.getAlgorithm());
    assertEquals(KeyUse.SIG, key.getUse());
    assertEquals(KeyStatus.ACTIVE, key.getStatus());
  }

  @Test
  @DisplayName("the kid is the thumbprint of the KMS public key")
  void kidFromPublicKey() {
    KmsEcNativeKeyProviderFactory factory = new KmsEcNativeKeyProviderFactory();
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, EC_KEY);
    factory.validateConfiguration(session, realm.model(), model);

    KeyWrapper key = only(factory.create(session, model));
    assertEquals(KeyUtils.createKeyId(kms.publicKey(EC_KEY)), key.getKid());
  }

  @Test
  @DisplayName("no private key material is stored anywhere — only an ARN")
  void nothingIsStoredButAPointer() {
    KmsEcNativeKeyProviderFactory factory = new KmsEcNativeKeyProviderFactory();
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, EC_KEY);
    factory.validateConfiguration(session, realm.model(), model);

    assertEquals(EC_KEY, model.get(KmsAttributes.KMS_KEY_ID));
    assertFalse(model.contains(Attributes.PRIVATE_KEY_KEY));
    assertFalse(model.contains(Attributes.SECRET_KEY));
    assertFalse(
        model.contains(KmsAttributes.WRAPPED_MATERIAL),
        "native mode holds no ciphertext either — there is nothing to wrap");
    assertNotNull(model.get(KmsAttributes.PUBLIC_KEY));
  }

  @Test
  @DisplayName("a disabled native provider contributes nothing")
  void disabled() {
    KmsEcNativeKeyProviderFactory factory = new KmsEcNativeKeyProviderFactory();
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, EC_KEY);
    factory.validateConfiguration(session, realm.model(), model);
    model.put(Attributes.ENABLED_KEY, false);
    assertEquals(0, factory.create(session, model).getKeysStream().count());
  }

  // ------------------------------------------------------------------ certificates

  @Test
  @DisplayName("RSA native mints a self-signed certificate by signing the TBS through the KMS")
  void rsaMintsACertificate() throws Exception {
    KmsRsaNativeKeyProviderFactory factory = new KmsRsaNativeKeyProviderFactory();
    ComponentModel model = component(KmsRsaNativeKeyProviderFactory.ID, RSA_KEY);
    factory.validateConfiguration(session, realm.model(), model);

    KeyWrapper key = only(factory.create(session, model));
    X509Certificate certificate = key.getCertificate();
    assertNotNull(certificate, "SAML descriptors read this");
    assertEquals("CN=customer-b", certificate.getSubjectX500Principal().getName());
    assertEquals(key.getPublicKey(), certificate.getPublicKey());
    // Self-signed by a key we cannot hold: the only proof it worked is that it verifies.
    certificate.verify(certificate.getPublicKey());
  }

  @Test
  @DisplayName("EC native has no certificate, matching stock ECDSA providers")
  void ecHasNoCertificateByDefault() {
    KmsEcNativeKeyProviderFactory factory = new KmsEcNativeKeyProviderFactory();
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, EC_KEY);
    factory.validateConfiguration(session, realm.model(), model);

    assertFalse(model.contains(Attributes.CERTIFICATE_KEY));
    assertNull(only(factory.create(session, model)).getCertificate());
  }

  // ------------------------------------------------------------------ bring your own key

  @Test
  @DisplayName("no key ARN is refused with the command that creates one")
  void keyIdRequired() {
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, null);
    ComponentValidationException e =
        assertThrows(
            ComponentValidationException.class,
            () ->
                new KmsEcNativeKeyProviderFactory()
                    .validateConfiguration(session, realm.model(), model));
    assertTrue(e.getMessage().contains("aws kms create-key"), e.getMessage());
    assertTrue(e.getMessage().contains("ECC_NIST_P256"), e.getMessage());
  }

  @Test
  @DisplayName("a symmetric key is refused: that is envelope mode's key, not this one's")
  void symmetricKeyRefused() {
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, "plain-symmetric");
    ComponentValidationException e =
        assertThrows(
            ComponentValidationException.class,
            () ->
                new KmsEcNativeKeyProviderFactory()
                    .validateConfiguration(session, realm.model(), model));
    assertTrue(e.getMessage().contains("SIGN_VERIFY"), e.getMessage());
  }

  @Test
  @DisplayName("an RSA key on the EC provider is refused before anything is written")
  void wrongKeySpecRefused() {
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, RSA_KEY);
    ComponentValidationException e =
        assertThrows(
            ComponentValidationException.class,
            () ->
                new KmsEcNativeKeyProviderFactory()
                    .validateConfiguration(session, realm.model(), model));
    assertTrue(e.getMessage().contains("ECC_"), e.getMessage());
    assertFalse(model.contains(KmsAttributes.PUBLIC_KEY));
  }

  @Test
  @DisplayName("revalidating an already-configured provider makes no KMS calls")
  void revalidationIsFree() {
    KmsEcNativeKeyProviderFactory factory = new KmsEcNativeKeyProviderFactory();
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, EC_KEY);
    factory.validateConfiguration(session, realm.model(), model);
    kms.reset();

    factory.validateConfiguration(session, realm.model(), model);
    assertEquals(0, kms.signs.get(), "a CMK's public half is immutable; re-reading it is waste");
  }

  @Test
  @DisplayName("a native provider with no cached public key fails legibly")
  void missingPublicKey() {
    ComponentModel model = component(KmsEcNativeKeyProviderFactory.ID, EC_KEY);
    model.put(Attributes.KID_KEY, "some-kid");
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> only(new KmsEcNativeKeyProviderFactory().create(session, model)));
    assertTrue(e.getMessage().contains("recreate"), e.getMessage());
  }

  @Test
  @DisplayName("neither native factory manufactures a fallback key")
  void noFallbackKeys() {
    assertFalse(
        new KmsEcNativeKeyProviderFactory()
            .createFallbackKeys(session, KeyUse.SIG, Algorithm.ES256));
    assertFalse(
        new KmsRsaNativeKeyProviderFactory()
            .createFallbackKeys(session, KeyUse.SIG, Algorithm.RS256));
  }

  @Test
  @DisplayName("both native factories advertise themselves as experimental")
  void helpTextSaysExperimental() {
    assertTrue(new KmsEcNativeKeyProviderFactory().getHelpText().contains("EXPERIMENTAL"));
    assertTrue(new KmsRsaNativeKeyProviderFactory().getHelpText().contains("EXPERIMENTAL"));
  }
}
