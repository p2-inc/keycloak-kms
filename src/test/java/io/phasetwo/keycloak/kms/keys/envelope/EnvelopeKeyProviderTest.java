package io.phasetwo.keycloak.kms.keys.envelope;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.keys.KeyCache;
import io.phasetwo.keycloak.kms.keys.KmsAttributes;
import io.phasetwo.keycloak.kms.keys.WrappedMaterial;
import io.phasetwo.keycloak.kms.local.LocalKmsProvider;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.testsupport.CountingKms;
import io.phasetwo.keycloak.kms.testsupport.Crypto;
import io.phasetwo.keycloak.kms.testsupport.FakeSession;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.KeyUtils;
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
import org.keycloak.models.RealmModel;

/** The envelope providers, against the local KMS backend. */
class EnvelopeKeyProviderTest {

  private static final byte[] KEK =
      "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
  private static final String REALM_ID = "11111111-2222-3333-4444-555555555555";

  private CountingKms kms;
  private RealmModel realm;
  private KeycloakSession session;
  private Map<String, ComponentModel> components;

  @BeforeAll
  static void bootCrypto() {
    Crypto.init();
  }

  @BeforeEach
  void setUp() {
    KeyCache.evictAll();
    kms = new CountingKms(new LocalKmsProvider(KEK, "test-cmk"));
    components = new HashMap<>();
    realm = FakeSession.realm(REALM_ID, "customer-a", components);
    session = FakeSession.session(kms, realm);
  }

  private ComponentModel component(String providerId) {
    ComponentModel model = new ComponentModel();
    model.setId("component-" + providerId);
    model.setName(providerId);
    model.setParentId(REALM_ID);
    model.setProviderId(providerId);
    model.setProviderType(KeyProvider.class.getName());
    model.setConfig(new org.keycloak.common.util.MultivaluedHashMap<>());
    model.put(Attributes.PRIORITY_KEY, 100L);
    return model;
  }

  // ------------------------------------------------------------------ RSA

  @Test
  @DisplayName("generation writes ciphertext and a certificate, and no plaintext private key")
  void rsaGenerationStoresNoPlaintext() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);

    assertTrue(WrappedMaterial.isWrapped(model.get(KmsAttributes.WRAPPED_MATERIAL)));
    assertNotNull(model.get(Attributes.CERTIFICATE_KEY));
    assertNotNull(model.get(Attributes.KID_KEY));

    // The audit finding, as an assertion: nothing in this component's config is a usable key.
    assertFalse(model.contains(Attributes.PRIVATE_KEY_KEY));
    assertFalse(model.contains(Attributes.SECRET_KEY));
    for (String value : flatten(model)) {
      assertFalse(
          value.contains("PRIVATE KEY"), "config value looks like a PEM private key: " + value);
    }
  }

  @Test
  @DisplayName("the kid is the RFC 7638 thumbprint stock would have produced")
  void kidMatchesStockDerivation() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);

    KeyWrapper key = only(factory.create(session, model));
    // This equivalence is what makes migration invisible to relying parties: a key moved into KMS
    // publishes under the same kid it had before.
    assertEquals(KeyUtils.createKeyId(key.getPublicKey()), key.getKid());
    assertEquals(model.get(Attributes.KID_KEY), key.getKid());
  }

  @Test
  @DisplayName(
      "the unwrapped private key actually signs, and the published certificate verifies it")
  void rsaKeySigns() throws Exception {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);

    KeyWrapper key = only(factory.create(session, model));
    assertEquals(KeyType.RSA, key.getType());
    assertEquals(Algorithm.RS256, key.getAlgorithm());
    assertEquals(KeyUse.SIG, key.getUse());
    assertEquals(KeyStatus.ACTIVE, key.getStatus());
    assertEquals(100L, key.getProviderPriority());

    byte[] message = "a token".getBytes(StandardCharsets.UTF_8);
    Signature signer = Signature.getInstance("SHA256withRSA");
    signer.initSign((java.security.PrivateKey) key.getPrivateKey());
    signer.update(message);
    byte[] signature = signer.sign();

    Signature verifier = Signature.getInstance("SHA256withRSA");
    verifier.initVerify(key.getCertificate().getPublicKey());
    verifier.update(message);
    assertTrue(verifier.verify(signature));
  }

  @Test
  @DisplayName("a fresh process reading the same config gets the same key — survives a restart")
  void survivesRestart() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);
    KeyWrapper before = only(factory.create(session, model));

    KeyCache.evictAll();
    CountingKms coldKms = new CountingKms(new LocalKmsProvider(KEK, "test-cmk"));
    KeycloakSession coldSession = FakeSession.session(coldKms, realm);
    KeyWrapper after = only(new KmsRsaKeyProviderFactory().create(coldSession, model));

    assertEquals(before.getKid(), after.getKid());
    assertEquals(before.getPublicKey(), after.getPublicKey());
    assertEquals(before.getPrivateKey(), after.getPrivateKey());
  }

  @Test
  @DisplayName("material sealed for one realm cannot be read by another")
  void realmIsolation() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);

    // Lift the whole component into another realm, as a database-level copy would.
    RealmModel other = FakeSession.realm("99999999-8888-7777-6666-555555555555", "customer-b");
    KeycloakSession otherSession = FakeSession.session(kms, other);
    ComponentModel copied = new ComponentModel(model);
    copied.setParentId(other.getId());

    KeyCache.evictAll();
    assertThrows(
        KmsException.class,
        () -> only(new KmsRsaKeyProviderFactory().create(otherSession, copied)));
  }

  @Test
  @DisplayName("an unsupported key size is refused before anything is generated")
  void keySizeValidated() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    model.put(Attributes.KEY_SIZE_KEY, 1234);
    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
    assertEquals(0, kms.encrypts.get(), "a rejected config must not have called the KMS");
  }

  @Test
  @DisplayName("a larger key size is honoured")
  void keySize4096() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    model.put(Attributes.KEY_SIZE_KEY, 4096);
    factory.validateConfiguration(session, realm, model);
    KeyWrapper key = only(factory.create(session, model));
    assertEquals(
        4096,
        ((java.security.interfaces.RSAPublicKey) key.getPublicKey()).getModulus().bitLength());
  }

  // ------------------------------------------------------------------ the seal read-back

  @Test
  @DisplayName("a KMS that cannot read back what it sealed fails the save rather than the realm")
  void sealVerifiesRoundTrip() {
    kms.corruptDecryptTo = "not the material".getBytes(StandardCharsets.UTF_8);
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);

    ComponentValidationException e =
        assertThrows(
            ComponentValidationException.class,
            () -> factory.validateConfiguration(session, realm, model));
    assertTrue(e.getMessage().contains("read back"), e.getMessage());
    assertFalse(
        model.contains(KmsAttributes.WRAPPED_MATERIAL),
        "a key that cannot be read back must not be persisted");
  }

  // ------------------------------------------------------------------ the carry-forward path

  @Test
  @DisplayName(
      "an update that drops the material reuses the stored key instead of minting a new one")
  void carriesMaterialForwardOnUpdate() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel stored = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, stored);
    components.put(stored.getId(), stored);
    String originalKid = stored.get(Attributes.KID_KEY);

    // What an admin console save of an unrelated field can look like: same component, new config
    // map, without the properties the console does not render.
    ComponentModel update = component(KmsRsaKeyProviderFactory.ID);
    update.put(Attributes.PRIORITY_KEY, 200L);
    factory.validateConfiguration(session, realm, update);

    assertEquals(
        originalKid,
        update.get(Attributes.KID_KEY),
        "regenerating here would change the kid and invalidate every live token");
    assertEquals(
        stored.get(KmsAttributes.WRAPPED_MATERIAL), update.get(KmsAttributes.WRAPPED_MATERIAL));
  }

  @Test
  @DisplayName("a genuinely new component with the same shape still generates fresh material")
  void generatesWhenNothingIsStored() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel a = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, a);

    ComponentModel b = component(KmsRsaKeyProviderFactory.ID);
    b.setId("component-second");
    factory.validateConfiguration(session, realm, b);

    assertNotEquals(a.get(Attributes.KID_KEY), b.get(Attributes.KID_KEY));
  }

  // ------------------------------------------------------------------ status and caching

  @Test
  @DisplayName("a disabled provider yields no key and makes no KMS call")
  void disabledMakesNoKmsCall() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);
    kms.reset();

    model.put(Attributes.ACTIVE_KEY, false);
    model.put(Attributes.ENABLED_KEY, false);

    assertEquals(0, factory.create(session, model).getKeysStream().count());
    assertEquals(0, kms.decrypts.get(), "a parked key should cost nothing");
  }

  @Test
  @DisplayName("an inactive but enabled key is published as passive, so old tokens still verify")
  void inactiveIsPassive() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);
    model.put(Attributes.ACTIVE_KEY, false);

    assertEquals(KeyStatus.PASSIVE, only(factory.create(session, model)).getStatus());
  }

  @Test
  @DisplayName("a warm key is served from memory — KMS is off the token path")
  void warmKeyDoesNotCallKms() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);
    kms.reset();

    only(factory.create(session, model));
    assertEquals(1, kms.decrypts.get());

    for (int i = 0; i < 50; i++) {
      only(factory.create(session, model));
    }
    assertEquals(1, kms.decrypts.get(), "the cache is what keeps KMS off the hot path");
  }

  @Test
  @DisplayName("changing the material invalidates the cache without any event")
  void cacheIsContentKeyed() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);
    only(factory.create(session, model));
    kms.reset();

    // Rotate in place: same component, new material. A cache keyed on the component id would keep
    // serving the old key until its TTL expired.
    ComponentModel replacement = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, replacement);
    model.put(KmsAttributes.WRAPPED_MATERIAL, replacement.get(KmsAttributes.WRAPPED_MATERIAL));
    model.put(Attributes.KID_KEY, replacement.get(Attributes.KID_KEY));
    model.put(Attributes.CERTIFICATE_KEY, replacement.get(Attributes.CERTIFICATE_KEY));
    // Generating the replacement itself cost a decrypt, in seal()'s read-back check.
    kms.reset();

    only(factory.create(session, model));
    assertEquals(1, kms.decrypts.get(), "new material must not be served from the old cache entry");
  }

  @Test
  @DisplayName("the encryption context names the realm, kid and key type")
  void encryptionContextIsBound() {
    KmsRsaKeyProviderFactory factory = new KmsRsaKeyProviderFactory();
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);
    kms.reset();
    only(factory.create(session, model));

    Map<String, String> context = kms.decryptContexts.get(0).asMap();
    assertEquals("keycloak", context.get("app"));
    assertEquals(REALM_ID, context.get("realm"));
    assertEquals(model.get(Attributes.KID_KEY), context.get("kid"));
    assertEquals("RSA", context.get("keyType"));
  }

  @Test
  @DisplayName("a component with no material at all fails with an explanation")
  void missingMaterial() {
    ComponentModel model = component(KmsRsaKeyProviderFactory.ID);
    model.put(Attributes.KID_KEY, "some-kid");
    KmsException e =
        assertThrows(
            KmsException.class, () -> only(new KmsRsaKeyProviderFactory().create(session, model)));
    assertTrue(e.getMessage().contains("no wrapped material"), e.getMessage());
  }

  // ------------------------------------------------------------------ the other key types

  @Test
  @DisplayName("RSA-enc produces an encryption key, not a signing one")
  void rsaEnc() {
    KmsRsaEncKeyProviderFactory factory = new KmsRsaEncKeyProviderFactory();
    ComponentModel model = component(KmsRsaEncKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);

    KeyWrapper key = only(factory.create(session, model));
    assertEquals(KeyUse.ENC, key.getUse());
    assertEquals(Algorithm.RSA_OAEP, key.getAlgorithm());
    assertEquals("RSA_ENC", kms.decryptContexts.get(0).asMap().get("keyType"));
  }

  @Test
  @DisplayName("HMAC produces a working MAC key of the configured size")
  void hmac() throws Exception {
    KmsHmacKeyProviderFactory factory = new KmsHmacKeyProviderFactory();
    ComponentModel model = component(KmsHmacKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);

    KeyWrapper key = only(factory.create(session, model));
    assertEquals(KeyType.OCT, key.getType());
    assertEquals(Algorithm.HS256, key.getAlgorithm());
    assertEquals(KeyUse.SIG, key.getUse());
    assertNotNull(key.getSecretKey());
    assertEquals(
        KmsHmacKeyProviderFactory.DEFAULT_SECRET_SIZE, key.getSecretKey().getEncoded().length);

    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(key.getSecretKey());
    assertEquals(32, mac.doFinal("action token".getBytes(StandardCharsets.UTF_8)).length);

    assertFalse(model.contains(Attributes.SECRET_KEY), "the secret must not be in config");
    assertTrue(WrappedMaterial.isWrapped(model.get(KmsAttributes.WRAPPED_MATERIAL)));
  }

  @Test
  @DisplayName("AES produces a 128-bit key by default")
  void aes() {
    KmsAesKeyProviderFactory factory = new KmsAesKeyProviderFactory();
    ComponentModel model = component(KmsAesKeyProviderFactory.ID);
    factory.validateConfiguration(session, realm, model);

    KeyWrapper key = only(factory.create(session, model));
    assertEquals(KeyType.OCT, key.getType());
    assertEquals(Algorithm.AES, key.getAlgorithm());
    assertEquals(KeyUse.ENC, key.getUse());
    assertEquals(16, key.getSecretKey().getEncoded().length);
    assertEquals("AES", kms.decryptContexts.get(0).asMap().get("keyType"));
  }

  @Test
  @DisplayName("an absurd secret size is refused")
  void secretSizeValidated() {
    KmsHmacKeyProviderFactory factory = new KmsHmacKeyProviderFactory();
    ComponentModel model = component(KmsHmacKeyProviderFactory.ID);
    model.put(Attributes.SECRET_SIZE_KEY, 4);
    assertThrows(
        ComponentValidationException.class,
        () -> factory.validateConfiguration(session, realm, model));
  }

  @Test
  @DisplayName("no factory ever manufactures a fallback key on a request path")
  void noFallbackKeys() {
    for (var factory :
        List.of(
            new KmsRsaKeyProviderFactory(),
            new KmsRsaEncKeyProviderFactory(),
            new KmsHmacKeyProviderFactory(),
            new KmsAesKeyProviderFactory())) {
      assertFalse(
          factory.createFallbackKeys(session, KeyUse.SIG, Algorithm.RS256),
          factory.getId() + " must not generate keys implicitly");
    }
  }

  @Test
  @DisplayName("every factory declares a KMS key override and a priority")
  void configPropertiesDeclared() {
    for (var factory :
        List.of(
            new KmsRsaKeyProviderFactory(),
            new KmsRsaEncKeyProviderFactory(),
            new KmsHmacKeyProviderFactory(),
            new KmsAesKeyProviderFactory())) {
      List<String> names =
          factory.getConfigProperties().stream()
              .map(org.keycloak.provider.ProviderConfigProperty::getName)
              .toList();
      assertTrue(names.contains(KmsAttributes.KMS_KEY_ID), factory.getId() + ": " + names);
      assertTrue(names.contains(Attributes.PRIORITY_KEY), factory.getId() + ": " + names);
      assertTrue(names.contains(Attributes.ACTIVE_KEY), factory.getId() + ": " + names);
      assertNotNull(factory.getHelpText());
    }
  }

  // ------------------------------------------------------------------ helpers

  private static KeyWrapper only(KeyProvider provider) {
    List<KeyWrapper> keys = provider.getKeysStream().toList();
    assertEquals(1, keys.size(), "expected exactly one key");
    return keys.get(0);
  }

  private static List<String> flatten(ComponentModel model) {
    return model.getConfig().values().stream().flatMap(List::stream).toList();
  }
}
