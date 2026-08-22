package io.phasetwo.keycloak.kms.migration;

import io.phasetwo.keycloak.kms.KmsConfig;
import io.phasetwo.keycloak.kms.keys.KmsAttributes;
import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import io.phasetwo.keycloak.kms.keys.WrappedMaterial;
import io.phasetwo.keycloak.kms.representation.MigratedKey;
import io.phasetwo.keycloak.kms.representation.MigrationReport;
import io.phasetwo.keycloak.kms.representation.RealmKmsStatus;
import io.phasetwo.keycloak.kms.representation.RotationResult;
import io.phasetwo.keycloak.kms.representation.SkippedKey;
import io.phasetwo.keycloak.kms.spi.EncryptionContext;
import io.phasetwo.keycloak.kms.spi.KmsProvider;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderFactory;

/**
 * Moves a realm's existing keys into the KMS without changing what relying parties see.
 *
 * <p>The invariant the whole design serves: <strong>every key JWKS publishes survives
 * unchanged</strong>. Same kid, same public key, same priority — so every token already issued
 * keeps verifying, no client re-fetches anything, and there is no window. (The <em>order</em> of
 * the JWK Set can change, since the migrated providers are new rows; a JWK Set is unordered by RFC
 * 7517 and clients select by kid.) That is only possible because
 * the kid a stock provider publishes is reproducible (config {@code kid}, else the RFC 7638
 * thumbprint), and it is why migration reads the existing material rather than generating new
 * material.
 *
 * <p>The legacy component is deactivated, never deleted. If any of this is wrong, re-enabling it is
 * a complete rollback; a deleted component is not recoverable. The operator is told exactly what to
 * delete, and can pass {@code deleteLegacy} once they believe it.
 */
@JBossLog
public class KmsKeyMigrator {

  /** What the log says once a key is safely in the KMS. This is the sentence the user asked for. */
  static final String SAFE_TO_DELETE =
      "It is now safe to delete the legacy provider. Until you do, the plaintext key is still in"
          + " your database.";

  private final KeycloakSession session;

  public KmsKeyMigrator(KeycloakSession session) {
    this.session = session;
  }

  // ------------------------------------------------------------------ migrate

  /**
   * Migrate every migratable key provider in a realm.
   *
   * <p>Idempotent: a realm already holding a KMS provider for a given key is reported as skipped
   * rather than migrated twice, so a failed run can simply be repeated.
   */
  public MigrationReport migrate(RealmModel realm, boolean deleteLegacy) {
    List<MigratedKey> migrated = new ArrayList<>();
    List<SkippedKey> skipped = new ArrayList<>();
    List<String> warnings = new ArrayList<>();

    List<ComponentModel> providers = keyProviders(realm);

    for (ComponentModel legacy : providers) {
      if (LegacyKeyReader.isKmsBacked(legacy)) {
        skipped.add(
            new SkippedKey(
                legacy.getProviderId(), legacy.getId(), "Already holds its material in the KMS."));
        continue;
      }
      String unsupported = LegacyKeyReader.unsupportedReason(legacy);
      if (unsupported != null) {
        skipped.add(new SkippedKey(legacy.getProviderId(), legacy.getId(), unsupported));
        continue;
      }
      if (!LegacyKeyReader.holdsPlaintext(legacy)) {
        skipped.add(
            new SkippedKey(
                legacy.getProviderId(), legacy.getId(), "No key material found in its config."));
        continue;
      }

      try {
        migrated.add(migrateOne(realm, legacy, deleteLegacy));
      } catch (RuntimeException e) {
        // One key failing must not abandon the others half-done; the report says which.
        log.errorf(
            e, "kms: could not migrate %s in realm %s", legacy.getProviderId(), realm.getName());
        skipped.add(
            new SkippedKey(
                legacy.getProviderId(),
                legacy.getId(),
                "Migration failed and was rolled back for this key: " + e.getMessage()));
      }
    }

    if (!migrated.isEmpty()) {
      warnings.add(
          "Migrated key material was previously stored in plaintext. It is in existing database"
              + " backups, snapshots, WAL and any read replicas. Encrypting it now stops further"
              + " exposure but does not undo past exposure — rotate to fresh KMS-generated material"
              + " once tokens signed by these kids have expired (POST .../kms/rotate).");
    }
    if (!deleteLegacy && !migrated.isEmpty()) {
      warnings.add(
          "The legacy providers are deactivated but still present, and their rows in"
              + " COMPONENT_CONFIG still contain plaintext key material. Delete them in the admin"
              + " console (Realm settings -> Keys -> Providers), or re-run with"
              + " ?deleteLegacy=true.");
    }

    boolean plaintextRemains =
        keyProviders(realm).stream().anyMatch(LegacyKeyReader::holdsPlaintext);
    if (plaintextRemains && migrated.isEmpty() && skipped.isEmpty()) {
      warnings.add("This realm has no key providers this extension can migrate.");
    }

    return new MigrationReport(realm.getName(), migrated, skipped, plaintextRemains, warnings);
  }

  private MigratedKey migrateOne(RealmModel realm, ComponentModel legacy, boolean deleteLegacy) {
    LegacyKey key = LegacyKeyReader.read(legacy);
    try {
      KmsProvider kms = requireKms();
      EncryptionContext context =
          EncryptionContext.forKey(realm.getId(), key.kid(), key.type().contextValue());

      // Seal first. This is the only step that can fail on something outside the database, so it
      // happens before any write — a KMS problem then leaves the realm exactly as it was.
      String wrapped = WrappedMaterial.encode(kms.encrypt(null, key.material(), context));

      // Prove it reads back before committing to it. A ciphertext that cannot be decrypted would
      // otherwise surface at the next restart, as a realm that can no longer issue tokens.
      byte[] readBack = kms.decrypt(null, WrappedMaterial.decode(wrapped), context);
      if (!java.util.Arrays.equals(key.material(), readBack)) {
        throw new IllegalStateException(
            "the KMS returned different material than it was given; nothing has been changed");
      }
      java.util.Arrays.fill(readBack, (byte) 0);

      ComponentModel replacement = buildReplacement(realm, legacy, key, wrapped);
      ComponentModel created = realm.addComponentModel(replacement);

      // Only now retire the original. Both exist for the width of this transaction; the legacy one
      // is disabled in the same transaction so no duplicate kid ever reaches JWKS.
      legacy.put(Attributes.ACTIVE_KEY, false);
      legacy.put(Attributes.ENABLED_KEY, false);
      realm.updateComponent(legacy);

      if (deleteLegacy) {
        realm.removeComponent(legacy);
        log.infof(
            "kms: realm '%s': %s (kid %s) is now held in the KMS, and the legacy %s provider has"
                + " been deleted along with its plaintext key.",
            realm.getName(), key.type(), key.kid(), legacy.getProviderId());
      } else {
        log.warnf(
            "kms: realm '%s': key material for kid %s is now held in the KMS. The legacy provider"
                + " '%s' (component %s) is deactivated but its row in COMPONENT_CONFIG STILL"
                + " CONTAINS THE PLAINTEXT %s. %s%n"
                + "  Admin console -> Realm settings -> Keys -> Providers -> delete '%s'%n"
                + "  or: DELETE /admin/realms/%s/components/%s",
            realm.getName(),
            key.kid(),
            legacy.getProviderId(),
            legacy.getId(),
            LegacyKeyReader.plaintextConfigKey(legacy),
            SAFE_TO_DELETE,
            legacy.getProviderId(),
            realm.getName(),
            legacy.getId());
      }

      return new MigratedKey(
          key.type().name(),
          key.kid(),
          legacy.getProviderId(),
          key.targetProviderId(),
          legacy.getId(),
          created.getId(),
          deleteLegacy);
    } finally {
      key.destroy();
    }
  }

  /** Build the KMS component: same kid, same priority, same public material. */
  private ComponentModel buildReplacement(
      RealmModel realm, ComponentModel legacy, LegacyKey key, String wrapped) {
    ComponentModel model = new ComponentModel();
    model.setName(legacy.getName() == null ? key.targetProviderId() : legacy.getName() + " (KMS)");
    model.setParentId(realm.getId());
    model.setProviderId(key.targetProviderId());
    model.setProviderType(KeyProvider.class.getName());

    MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
    // Pin the kid explicitly rather than letting it be re-derived. Derivation is deterministic
    // today, but a pinned value cannot drift if a future Keycloak changes how it computes one.
    config.putSingle(Attributes.KID_KEY, key.kid());
    config.putSingle(Attributes.PRIORITY_KEY, String.valueOf(key.priority()));
    config.putSingle(
        Attributes.ACTIVE_KEY, String.valueOf(legacy.get(Attributes.ACTIVE_KEY, true)));
    config.putSingle(
        Attributes.ENABLED_KEY, String.valueOf(legacy.get(Attributes.ENABLED_KEY, true)));
    config.putSingle(KmsAttributes.WRAPPED_MATERIAL, wrapped);
    if (key.algorithm() != null) {
      config.putSingle(Attributes.ALGORITHM_KEY, key.algorithm());
    }
    if (key.certificatePem() != null) {
      config.putSingle(Attributes.CERTIFICATE_KEY, key.certificatePem());
    }
    // Provenance, so a later reader can see where this came from without consulting a changelog.
    config.putSingle(KmsAttributes.MIGRATED_FROM, legacy.getId());
    config.putSingle(KmsAttributes.MIGRATED_FROM_PROVIDER, legacy.getProviderId());
    model.setConfig(config);
    return model;
  }

  // ------------------------------------------------------------------ rotate

  /**
   * Add a fresh KMS-generated key of one type, at a higher priority than anything already there.
   *
   * <p>This is the second half of the migration story. Migrated material was once in plaintext in
   * the database; only material generated after the move has never been exposed. Standard Keycloak
   * rotation semantics apply — the previous keys stay published so tokens already issued keep
   * verifying, and the operator retires them when those tokens have expired.
   */
  public RotationResult rotate(RealmModel realm, KmsKeyType type) {
    String providerId = LegacyKeyReader.targetProviderFor(type);

    List<ComponentModel> existing =
        keyProviders(realm).stream()
            .filter(c -> providerId.equals(c.getProviderId()) || sameStockType(c, type))
            .toList();
    long newPriority =
        existing.stream().mapToLong(c -> c.get(Attributes.PRIORITY_KEY, 0L)).max().orElse(0L) + 100;

    ComponentModel model = new ComponentModel();
    model.setName(providerId + " (rotated)");
    model.setParentId(realm.getId());
    model.setProviderId(providerId);
    model.setProviderType(KeyProvider.class.getName());
    MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
    config.putSingle(Attributes.PRIORITY_KEY, String.valueOf(newPriority));
    model.setConfig(config);

    // addComponentModel runs the factory's validateConfiguration, which is what generates and
    // seals the material — so the new key is created the same way any other one is.
    ComponentModel created = realm.addComponentModel(model);
    ComponentModel stored = realm.getComponent(created.getId());
    String newKid = (stored == null ? created : stored).get(Attributes.KID_KEY);

    List<String> previousKids =
        existing.stream()
            .map(c -> c.get(Attributes.KID_KEY))
            .filter(Objects::nonNull)
            .filter(k -> !k.equals(newKid))
            .toList();

    log.infof(
        "kms: realm '%s': rotated %s onto a new KMS-generated key (kid %s, priority %d). %d"
            + " previous key(s) remain published for verification.",
        realm.getName(), type, newKid, newPriority, previousKids.size());

    return new RotationResult(
        realm.getName(),
        type.name(),
        newKid,
        created.getId(),
        newPriority,
        previousKids,
        List.of(
            "New tokens are signed with kid " + newKid + " from now on.",
            "Leave the previous providers in place until every token they signed has expired —"
                + " at minimum the realm's access-token lifespan, and longer if refresh tokens or"
                + " offline sessions are in play.",
            "Then set them inactive (active=false) to stop publishing them, and delete them once"
                + " nothing complains."));
  }

  private static boolean sameStockType(ComponentModel model, KmsKeyType type) {
    for (String stock : type.stockProviderIds()) {
      if (stock.equals(model.getProviderId())) {
        return true;
      }
    }
    return false;
  }

  // ------------------------------------------------------------------ status

  /** What this realm's key providers look like, and whether any plaintext is left. */
  public RealmKmsStatus status(RealmModel realm) {
    List<RealmKmsStatus.KeyProviderStatus> keys =
        keyProviders(realm).stream()
            .sorted(
                Comparator.comparingLong((ComponentModel c) -> c.get(Attributes.PRIORITY_KEY, 0L))
                    .reversed())
            .map(
                c ->
                    new RealmKmsStatus.KeyProviderStatus(
                        c.getId(),
                        c.getProviderId(),
                        c.get(Attributes.KID_KEY),
                        LegacyKeyReader.isKmsBacked(c),
                        LegacyKeyReader.holdsPlaintext(c),
                        c.get(Attributes.ACTIVE_KEY, true),
                        c.get(Attributes.ENABLED_KEY, true),
                        c.get(Attributes.PRIORITY_KEY, 0L)))
            .toList();

    return new RealmKmsStatus(
        realm.getName(),
        KmsConfig.backendId(),
        keys,
        keys.stream().anyMatch(RealmKmsStatus.KeyProviderStatus::holdsPlaintext));
  }

  // ------------------------------------------------------------------ helpers

  private List<ComponentModel> keyProviders(RealmModel realm) {
    return realm.getComponentsStream(realm.getId(), KeyProvider.class.getName()).toList();
  }

  private KmsProvider requireKms() {
    KmsProvider kms = session.getProvider(KmsProvider.class);
    if (kms == null) {
      throw new IllegalStateException(
          "No KMS backend is configured. Set --spi-kms--provider=aws before migrating.");
    }
    return kms;
  }

  /** Whether any KMS key provider factory is registered — used by the startup sweep. */
  public static boolean extensionIsUsable(KeycloakSession session) {
    return session
        .getKeycloakSessionFactory()
        .getProviderFactoriesStream(KeyProvider.class)
        .map(ProviderFactory::getId)
        .anyMatch(id -> id.startsWith("kms-"));
  }
}
