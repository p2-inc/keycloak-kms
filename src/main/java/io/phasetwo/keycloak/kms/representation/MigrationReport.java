package io.phasetwo.keycloak.kms.representation;

import java.util.List;

/**
 * The outcome of migrating one realm.
 *
 * @param realm the realm name
 * @param migrated keys now held as KMS ciphertext
 * @param skipped providers left alone, each with a reason
 * @param plaintextRemains true while any component in this realm still holds usable key material —
 *     the single field that answers "is the audit finding closed?"
 * @param warnings things the operator needs to read, including the reminder that migrated material
 *     was previously at rest in plaintext and is in existing backups
 */
public record MigrationReport(
    String realm,
    List<MigratedKey> migrated,
    List<SkippedKey> skipped,
    boolean plaintextRemains,
    List<String> warnings) {}
