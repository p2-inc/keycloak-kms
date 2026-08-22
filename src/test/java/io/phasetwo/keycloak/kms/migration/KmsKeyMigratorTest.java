package io.phasetwo.keycloak.kms.migration;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.phasetwo.keycloak.kms.keys.KeyCache;
import io.phasetwo.keycloak.kms.keys.KmsAttributes;
import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import io.phasetwo.keycloak.kms.keys.WrappedMaterial;
import io.phasetwo.keycloak.kms.keys.envelope.KmsAesKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsHmacKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaKeyProviderFactory;
import io.phasetwo.keycloak.kms.local.LocalKmsProvider;
import io.phasetwo.keycloak.kms.representation.MigratedKey;
import io.phasetwo.keycloak.kms.representation.MigrationReport;
import io.phasetwo.keycloak.kms.representation.RealmKmsStatus;
import io.phasetwo.keycloak.kms.representation.RotationResult;
import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsException;
import io.phasetwo.keycloak.kms.testsupport.CountingKms;
import io.phasetwo.keycloak.kms.testsupport.Crypto;
import io.phasetwo.keycloak.kms.testsupport.FakeRealm;
import io.phasetwo.keycloak.kms.testsupport.FakeSession;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.models.KeycloakSession;

/**
 * Migration, against realistically-seeded stock key providers.
 *
 * <p>The seeded components are built the way Keycloak builds them — a real RSA keypair, a real
 * self-signed certificate, PEM in {@code privateKey}, Base64Url in {@code secret} — because the
 * failure this code most plausibly has is reading one of those encodings slightly wrong, and a
 * fixture that stored the bytes some other way would hide it.
 */
class KmsKeyMigratorTest {

  private static final byte[] KEK =
      "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);
  private static final String REALM_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

  private CountingKms kms;
  private FakeRealm realm;
  private KeycloakSession session;
  private KmsKeyMigrator migrator;

  private KeyPair seededRsaPair;
  private byte[] seededHmacSecret;

  @BeforeAll
  static void bootCrypto() {
    Crypto.init();
  }

  @BeforeEach
  void setUp() {
    KeyCache.evictAll();
    kms = new CountingKms(new LocalKmsProvider(KEK, "test-cmk"));
    realm = new FakeRealm(REALM_ID, "customer-a");
    session = FakeSession.session(kms, realm.model());
    realm.setSession(session);
    migrator = new KmsKeyMigrator(session);
  }

  // ------------------------------------------------------------------ seeding

  /** A component shaped exactly like what {@code rsa-generated} writes. */
  private ComponentModel seedStockRsa(long priority) {
    seededRsaPair = KeyUtils.generateRsaKeyPair(2048);
    X509Certificate cert =
        CertificateUtils.generateV1SelfSignedCertificate(seededRsaPair, "customer-a");
    Map<String, String> config = new HashMap<>();
    config.put(Attributes.PRIVATE_KEY_KEY, PemUtils.encodeKey(seededRsaPair.getPrivate()));
    config.put(Attributes.CERTIFICATE_KEY, PemUtils.encodeCertificate(cert));
    config.put(Attributes.PRIORITY_KEY, String.valueOf(priority));
    config.put(Attributes.ALGORITHM_KEY, Algorithm.RS256);
    return realm.seed("rsa-generated", config);
  }

  private ComponentModel seedStockHmac(String kid) {
    seededHmacSecret = new byte[64];
    new java.security.SecureRandom().nextBytes(seededHmacSecret);
    Map<String, String> config = new HashMap<>();
    // Base64Url, as stock writes it.
    config.put(Attributes.SECRET_KEY, Base64Url.encode(seededHmacSecret));
    config.put(Attributes.SECRET_SIZE_KEY, "64");
    config.put(Attributes.KID_KEY, kid);
    config.put(Attributes.PRIORITY_KEY, "100");
    config.put(Attributes.ALGORITHM_KEY, Algorithm.HS256);
    return realm.seed("hmac-generated", config);
  }

  private ComponentModel seedStockAes() {
    byte[] secret = new byte[16];
    new java.security.SecureRandom().nextBytes(secret);
    Map<String, String> config = new HashMap<>();
    config.put(Attributes.SECRET_KEY, Base64Url.encode(secret));
    config.put(Attributes.KID_KEY, "aes-kid");
    config.put(Attributes.PRIORITY_KEY, "100");
    return realm.seed("aes-generated", config);
  }

  private ComponentModel migratedComponent(MigrationReport report, String type) {
    MigratedKey key =
        report.migrated().stream()
            .filter(m -> m.keyType().equals(type))
            .findFirst()
            .orElseThrow(() -> new AssertionError("no migrated " + type + " in " + report));
    return realm.component(key.newComponentId());
  }

  // ------------------------------------------------------------------ the headline

  @Test
  @DisplayName("migration preserves the kid and the public key — JWKS does not change")
  void jwksIsUnchanged() {
    ComponentModel legacy = seedStockRsa(100);
    String expectedKid = KeyUtils.createKeyId(seededRsaPair.getPublic());

    MigrationReport report = migrator.migrate(realm.model(), false);

    assertEquals(1, report.migrated().size(), report.toString());
    MigratedKey migrated = report.migrated().get(0);
    assertEquals("RSA", migrated.keyType());
    assertEquals(expectedKid, migrated.kid(), "the kid must survive the move");
    assertEquals("rsa-generated", migrated.from());
    assertEquals(KmsRsaKeyProviderFactory.ID, migrated.to());
    assertEquals(legacy.getId(), migrated.legacyComponentId());

    // Load the migrated key the way Keycloak would, and compare it to what was there before.
    KeyWrapper key = loadKey(migratedComponent(report, "RSA"), new KmsRsaKeyProviderFactory());
    assertEquals(expectedKid, key.getKid());
    assertEquals(seededRsaPair.getPublic(), key.getPublicKey());
    assertEquals(seededRsaPair.getPrivate(), key.getPrivateKey());
    assertEquals(100L, key.getProviderPriority(), "priority drives which key signs");
    assertEquals(Algorithm.RS256, key.getAlgorithm());
  }

  @Test
  @DisplayName("a token signed before migration still verifies after it")
  void preMigrationTokensStillVerify() throws Exception {
    seedStockRsa(100);
    byte[] token = "a token issued yesterday".getBytes(StandardCharsets.UTF_8);
    java.security.Signature signer = java.security.Signature.getInstance("SHA256withRSA");
    signer.initSign(seededRsaPair.getPrivate());
    signer.update(token);
    byte[] signature = signer.sign();

    MigrationReport report = migrator.migrate(realm.model(), true);
    KeyWrapper key = loadKey(migratedComponent(report, "RSA"), new KmsRsaKeyProviderFactory());

    java.security.Signature verifier = java.security.Signature.getInstance("SHA256withRSA");
    verifier.initVerify((PublicKey) key.getPublicKey());
    verifier.update(token);
    assertTrue(verifier.verify(signature), "the migrated key must verify pre-migration signatures");
  }

  // ------------------------------------------------------------------ what happens to the legacy

  @Test
  @DisplayName("by default the legacy provider is deactivated, not deleted")
  void legacyIsDeactivatedNotDeleted() {
    ComponentModel legacy = seedStockRsa(100);
    MigrationReport report = migrator.migrate(realm.model(), false);

    ComponentModel after = realm.component(legacy.getId());
    assertNotNull(after, "deleting is the operator's call, not ours — it is the only rollback");
    assertFalse(after.get(Attributes.ACTIVE_KEY, true));
    assertFalse(after.get(Attributes.ENABLED_KEY, true));
    assertTrue(after.contains(Attributes.PRIVATE_KEY_KEY), "the plaintext is still there");

    assertTrue(report.plaintextRemains());
    assertTrue(report.migrated().get(0).legacyDeleted() == false);
    assertTrue(
        report.warnings().stream().anyMatch(w -> w.contains("COMPONENT_CONFIG")),
        "the operator must be told the plaintext is still in the database: " + report.warnings());
  }

  @Test
  @DisplayName("a disabled legacy provider contributes no key, so no duplicate kid reaches JWKS")
  void deactivatedLegacyPublishesNothing() {
    seedStockRsa(100);
    MigrationReport report = migrator.migrate(realm.model(), false);

    long publishedWithThatKid =
        realm.components().stream()
            .filter(c -> report.migrated().get(0).kid().equals(c.get(Attributes.KID_KEY)))
            .filter(c -> c.get(Attributes.ENABLED_KEY, true))
            .count();
    assertEquals(1, publishedWithThatKid, "exactly one enabled provider may publish a given kid");
  }

  @Test
  @DisplayName("deleteLegacy removes the plaintext and closes the finding")
  void deleteLegacyClosesTheFinding() {
    ComponentModel legacy = seedStockRsa(100);
    seedStockHmac("hmac-kid");
    seedStockAes();

    MigrationReport report = migrator.migrate(realm.model(), true);

    assertEquals(3, report.migrated().size(), report.toString());
    assertNull(realm.component(legacy.getId()));
    assertFalse(report.plaintextRemains(), "nothing in this realm should hold plaintext now");
    for (ComponentModel c : realm.components()) {
      assertFalse(c.contains(Attributes.PRIVATE_KEY_KEY), c.getProviderId());
      assertFalse(c.contains(Attributes.SECRET_KEY), c.getProviderId());
      assertTrue(WrappedMaterial.isWrapped(c.get(KmsAttributes.WRAPPED_MATERIAL)));
    }
  }

  // ------------------------------------------------------------------ secrets

  @Test
  @DisplayName("an HMAC secret round-trips byte-for-byte, Base64Url and all")
  void hmacSecretSurvivesExactly() {
    seedStockHmac("the-existing-hmac-kid");
    MigrationReport report = migrator.migrate(realm.model(), true);

    KeyWrapper key = loadKey(migratedComponent(report, "HMAC"), new KmsHmacKeyProviderFactory());
    assertEquals("the-existing-hmac-kid", key.getKid(), "an explicit kid must be preserved");
    assertArrayEquals(
        seededHmacSecret,
        key.getSecretKey().getEncoded(),
        "Base64Url vs Base64 here would give the right length and the wrong bytes");
    assertEquals(Algorithm.HS256, key.getAlgorithm());
  }

  @Test
  @DisplayName("an AES key migrates as an encryption key")
  void aesMigrates() {
    seedStockAes();
    MigrationReport report = migrator.migrate(realm.model(), true);
    KeyWrapper key = loadKey(migratedComponent(report, "AES"), new KmsAesKeyProviderFactory());
    assertEquals("aes-kid", key.getKid());
    assertEquals(16, key.getSecretKey().getEncoded().length);
  }

  // ------------------------------------------------------------------ what it refuses to do

  @Test
  @DisplayName("an EC key is reported as left behind rather than quietly ignored")
  void ecKeyIsReportedNotIgnored() {
    seedStockRsa(100);
    realm.seed(
        "ecdsa-generated",
        Map.of(
            Attributes.PRIVATE_KEY_KEY, "MHcCAQEE...",
            Attributes.KID_KEY, "ec-kid",
            Attributes.PRIORITY_KEY, "100"));

    MigrationReport report = migrator.migrate(realm.model(), true);

    assertEquals(1, report.migrated().size());
    assertEquals(1, report.skipped().size());
    assertEquals("ecdsa-generated", report.skipped().get(0).providerId());
    assertTrue(report.skipped().get(0).reason().contains("ECDSA"), report.skipped().toString());
    assertTrue(
        report.plaintextRemains(),
        "a realm with an unmigrated EC key has not closed the finding, and must not say it has");
  }

  @Test
  @DisplayName("running twice is a no-op, so a failed run can simply be repeated")
  void idempotent() {
    seedStockRsa(100);
    seedStockHmac("hmac-kid");
    MigrationReport first = migrator.migrate(realm.model(), true);
    assertEquals(2, first.migrated().size());

    MigrationReport second = migrator.migrate(realm.model(), true);
    assertEquals(0, second.migrated().size());
    assertEquals(2, second.skipped().size());
    assertTrue(second.skipped().stream().allMatch(s -> s.reason().contains("Already")));
    assertFalse(second.plaintextRemains());
  }

  @Test
  @DisplayName("a KMS failure on one key leaves that key untouched and still migrates the others")
  void oneFailureDoesNotAbandonTheRest() {
    seedStockRsa(100);
    ComponentModel hmac = seedStockHmac("hmac-kid");

    CountingKms failing =
        new CountingKms(new LocalKmsProvider(KEK, "test-cmk")) {
          @Override
          public byte[] encrypt(String keyId, byte[] plaintext, EncryptionContext context) {
            if ("HMAC".equals(context.asMap().get("keyType"))) {
              throw new KmsException("simulated KMS outage");
            }
            return super.encrypt(keyId, plaintext, context);
          }
        };
    KeycloakSession failingSession = FakeSession.session(failing, realm.model());
    realm.setSession(failingSession);

    MigrationReport report = new KmsKeyMigrator(failingSession).migrate(realm.model(), false);

    assertEquals(1, report.migrated().size());
    assertEquals("RSA", report.migrated().get(0).keyType());
    assertTrue(
        report.skipped().stream().anyMatch(s -> s.reason().contains("simulated KMS outage")),
        report.skipped().toString());

    ComponentModel hmacAfter = realm.component(hmac.getId());
    assertTrue(
        hmacAfter.get(Attributes.ENABLED_KEY, true),
        "a key that failed to migrate must be left working, not disabled");
    assertTrue(hmacAfter.contains(Attributes.SECRET_KEY));
  }

  @Test
  @DisplayName("a KMS that cannot read back what it wrote changes nothing at all")
  void roundTripFailureChangesNothing() {
    ComponentModel legacy = seedStockRsa(100);
    kms.corruptDecryptTo = "wrong".getBytes(StandardCharsets.UTF_8);

    MigrationReport report = migrator.migrate(realm.model(), false);

    assertEquals(0, report.migrated().size());
    assertEquals(1, report.skipped().size());
    ComponentModel after = realm.component(legacy.getId());
    assertTrue(after.get(Attributes.ENABLED_KEY, true), "the original must still be serving");
    assertEquals(
        1, realm.components().size(), "a half-written migration must not leave a stray component");
  }

  // ------------------------------------------------------------------ rotation

  @Test
  @DisplayName("rotation adds a new key above the migrated one and keeps the old one published")
  void rotation() {
    seedStockRsa(100);
    MigrationReport migration = migrator.migrate(realm.model(), true);
    String migratedKid = migration.migrated().get(0).kid();

    RotationResult result = migrator.rotate(realm.model(), KmsKeyType.RSA);

    assertNotNull(result.newKid());
    assertNotEquals(migratedKid, result.newKid(), "rotation must produce new material");
    assertEquals(200L, result.newPriority(), "the new key has to outrank the old one to sign");
    assertTrue(result.previousKids().contains(migratedKid));
    assertTrue(
        result.nextSteps().stream().anyMatch(s -> s.contains("expired")),
        "the operator needs to be told when it is safe to retire the old key");

    ComponentModel rotated = realm.component(result.newComponentId());
    assertTrue(WrappedMaterial.isWrapped(rotated.get(KmsAttributes.WRAPPED_MATERIAL)));
    assertFalse(rotated.contains(Attributes.PRIVATE_KEY_KEY));
  }

  @Test
  @DisplayName("rotating a realm that has never been migrated still works")
  void rotateFromNothing() {
    RotationResult result = migrator.rotate(realm.model(), KmsKeyType.RSA);
    assertNotNull(result.newKid());
    assertEquals(100L, result.newPriority());
    assertTrue(result.previousKids().isEmpty());
  }

  // ------------------------------------------------------------------ status

  @Test
  @DisplayName("status names every provider and answers the audit question directly")
  void status() {
    seedStockRsa(100);
    seedStockHmac("hmac-kid");

    RealmKmsStatus before = migrator.status(realm.model());
    assertEquals("customer-a", before.realm());
    assertEquals(2, before.keys().size());
    assertTrue(before.plaintextRemains());
    assertTrue(before.keys().stream().noneMatch(RealmKmsStatus.KeyProviderStatus::kmsBacked));

    migrator.migrate(realm.model(), true);

    RealmKmsStatus after = migrator.status(realm.model());
    assertEquals(2, after.keys().size());
    assertFalse(after.plaintextRemains());
    assertTrue(after.keys().stream().allMatch(RealmKmsStatus.KeyProviderStatus::kmsBacked));
    assertTrue(after.keys().stream().noneMatch(RealmKmsStatus.KeyProviderStatus::holdsPlaintext));
  }

  @Test
  @DisplayName("status sorts by priority, so the signing key is first")
  void statusIsOrdered() {
    seedStockRsa(50);
    realm.seed(
        "rsa-generated",
        Map.of(
            Attributes.PRIVATE_KEY_KEY,
            PemUtils.encodeKey(KeyUtils.generateRsaKeyPair(2048).getPrivate()),
            Attributes.PRIORITY_KEY,
            "300"));

    List<Long> priorities =
        migrator.status(realm.model()).keys().stream()
            .map(RealmKmsStatus.KeyProviderStatus::priority)
            .toList();
    assertEquals(List.of(300L, 50L), priorities);
  }

  // ------------------------------------------------------------------ the warning nobody should
  // miss

  @Test
  @DisplayName("the report says migrated material was already exposed and must still be rotated")
  void reportWarnsAboutPriorExposure() {
    seedStockRsa(100);
    MigrationReport report = migrator.migrate(realm.model(), true);

    Optional<String> warning =
        report.warnings().stream().filter(w -> w.contains("backups")).findFirst();
    assertTrue(warning.isPresent(), report.warnings().toString());
    assertTrue(warning.get().contains("rotate"), warning.get());
  }

  // ------------------------------------------------------------------ helpers

  private KeyWrapper loadKey(ComponentModel model, Object factory) {
    KeyCache.evictAll();
    org.keycloak.keys.KeyProviderFactory<?> f = (org.keycloak.keys.KeyProviderFactory<?>) factory;
    List<KeyWrapper> keys =
        ((org.keycloak.keys.KeyProvider) f.create(session, model)).getKeysStream().toList();
    assertEquals(1, keys.size());
    return keys.get(0);
  }
}
