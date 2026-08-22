package io.phasetwo.keycloak.kms.representation;

/**
 * One key that moved into the KMS.
 *
 * @param keyType RSA, RSA_ENC, HMAC or AES
 * @param kid unchanged by the migration — that is the headline
 * @param from the stock provider id it came from
 * @param to the KMS provider id that now holds it
 * @param legacyComponentId the component still holding plaintext, for the operator to delete
 * @param newComponentId the component created by this migration
 * @param legacyDeleted whether this run deleted the legacy component
 */
public record MigratedKey(
    String keyType,
    String kid,
    String from,
    String to,
    String legacyComponentId,
    String newComponentId,
    boolean legacyDeleted) {}
