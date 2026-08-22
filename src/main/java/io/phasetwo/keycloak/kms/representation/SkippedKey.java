package io.phasetwo.keycloak.kms.representation;

/**
 * A key provider the migration did not touch, and why.
 *
 * <p>Reported as prominently as the successes. A realm reported as "migrated" while an EC key still
 * sits in plaintext would be worse than no report at all.
 */
public record SkippedKey(String providerId, String componentId, String reason) {}
