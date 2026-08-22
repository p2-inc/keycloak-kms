package io.phasetwo.keycloak.kms.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.keys.KeyCache;
import io.phasetwo.keycloak.kms.keys.KmsAttributes;
import io.phasetwo.keycloak.kms.keys.WrappedMaterial;
import io.phasetwo.keycloak.kms.keys.envelope.KmsAesKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsHmacKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaEncKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaKeyProviderFactory;
import io.phasetwo.keycloak.kms.local.LocalKmsProvider;
import io.phasetwo.keycloak.kms.testsupport.CountingKms;
import io.phasetwo.keycloak.kms.testsupport.Crypto;
import io.phasetwo.keycloak.kms.testsupport.FakeRealm;
import io.phasetwo.keycloak.kms.testsupport.FakeSession;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.Attributes;
import org.keycloak.models.KeycloakSession;

/** The new-realm installer, which is the half of bootstrap that is testable without a server. */
class KmsBootstrapTest {

  private static final byte[] KEK =
      "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

  private FakeRealm realm;
  private KeycloakSession session;

  @BeforeAll
  static void bootCrypto() {
    Crypto.init();
  }

  @BeforeEach
  void setUp() {
    KeyCache.evictAll();
    realm = new FakeRealm("realm-id", "brand-new");
    session = FakeSession.session(new CountingKms(new LocalKmsProvider(KEK, "cmk")), realm.model());
    realm.setSession(session);
  }

  /** What Keycloak's DefaultKeyProviders leaves behind on a freshly created realm. */
  private void seedStockDefaults() {
    realm.seed(
        "rsa-generated",
        Map.of(
            Attributes.PRIVATE_KEY_KEY,
            PemUtils.encodeKey(KeyUtils.generateRsaKeyPair(2048).getPrivate()),
            Attributes.PRIORITY_KEY,
            "100"));
    realm.seed(
        "rsa-enc-generated",
        Map.of(
            Attributes.PRIVATE_KEY_KEY,
            PemUtils.encodeKey(KeyUtils.generateRsaKeyPair(2048).getPrivate()),
            Attributes.PRIORITY_KEY,
            "100"));
    realm.seed(
        "hmac-generated",
        Map.of(Attributes.SECRET_KEY, "c2VjcmV0", Attributes.PRIORITY_KEY, "100"));
    realm.seed(
        "aes-generated", Map.of(Attributes.SECRET_KEY, "c2VjcmV0", Attributes.PRIORITY_KEY, "100"));
  }

  @Test
  @DisplayName("a new realm's stock providers are replaced, leaving no key material behind")
  void replacesStockDefaults() {
    seedStockDefaults();
    KmsBootstrap.installDefaults(realm.model());

    List<String> providerIds =
        realm.components().stream().map(ComponentModel::getProviderId).sorted().toList();
    assertEquals(
        List.of(
            KmsAesKeyProviderFactory.ID,
            KmsHmacKeyProviderFactory.ID,
            KmsRsaEncKeyProviderFactory.ID,
            KmsRsaKeyProviderFactory.ID),
        providerIds);

    for (ComponentModel c : realm.components()) {
      assertTrue(
          WrappedMaterial.isWrapped(c.get(KmsAttributes.WRAPPED_MATERIAL)), c.getProviderId());
      assertFalse(c.contains(Attributes.PRIVATE_KEY_KEY), c.getProviderId());
      assertFalse(c.contains(Attributes.SECRET_KEY), c.getProviderId());
    }
  }

  @Test
  @DisplayName("priority is carried over, so the realm behaves the same as it would have")
  void preservesPriority() {
    realm.seed(
        "rsa-generated",
        Map.of(
            Attributes.PRIVATE_KEY_KEY,
            PemUtils.encodeKey(KeyUtils.generateRsaKeyPair(2048).getPrivate()),
            Attributes.PRIORITY_KEY,
            "250"));

    KmsBootstrap.installDefaults(realm.model());

    assertEquals(1, realm.components().size());
    assertEquals(250L, realm.components().get(0).get(Attributes.PRIORITY_KEY, 0L));
  }

  @Test
  @DisplayName("deleting the stock provider is safe here: it is seconds old and has signed nothing")
  void deletesTheReplacedProvider() {
    seedStockDefaults();
    int before = realm.components().size();
    KmsBootstrap.installDefaults(realm.model());
    assertEquals(before, realm.components().size(), "one-for-one, not additive");
  }

  @Test
  @DisplayName("a realm with no stock providers is left alone")
  void noStockProvidersIsANoOp() {
    KmsBootstrap.installDefaults(realm.model());
    assertTrue(realm.components().isEmpty());
  }

  @Test
  @DisplayName("running twice does not double the providers")
  void idempotent() {
    seedStockDefaults();
    KmsBootstrap.installDefaults(realm.model());
    int after = realm.components().size();
    KmsBootstrap.installDefaults(realm.model());
    assertEquals(after, realm.components().size());
  }
}
