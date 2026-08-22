package io.phasetwo.keycloak.kms.representation;

import java.util.List;

/**
 * The outcome of rotating one key type onto fresh KMS-held material.
 *
 * @param realm the realm name
 * @param keyType what was rotated
 * @param newKid the kid now signing
 * @param newComponentId the provider created
 * @param newPriority its priority, above every existing provider of this type
 * @param previousKids kids still published for verification
 * @param nextSteps what the operator has to do, and when
 */
public record RotationResult(
    String realm,
    String keyType,
    String newKid,
    String newComponentId,
    long newPriority,
    List<String> previousKids,
    List<String> nextSteps) {}
