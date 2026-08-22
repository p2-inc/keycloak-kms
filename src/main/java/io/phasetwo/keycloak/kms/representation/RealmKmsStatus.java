package io.phasetwo.keycloak.kms.representation;

import java.util.List;

/**
 * What a realm's key providers look like right now.
 *
 * @param realm the realm name
 * @param backend the configured KMS backend id, or null if none
 * @param keys one entry per key provider
 * @param plaintextRemains whether any provider still holds usable key material in the database
 */
public record RealmKmsStatus(
    String realm, String backend, List<KeyProviderStatus> keys, boolean plaintextRemains) {

  /**
   * @param componentId the component
   * @param providerId e.g. rsa-generated or kms-rsa-generated
   * @param kid the key id, when the provider records one
   * @param kmsBacked whether this extension holds the material
   * @param holdsPlaintext whether usable key material sits in COMPONENT_CONFIG
   * @param active whether the provider is currently signing
   * @param enabled whether the provider contributes keys at all
   * @param priority the provider's priority
   */
  public record KeyProviderStatus(
      String componentId,
      String providerId,
      String kid,
      boolean kmsBacked,
      boolean holdsPlaintext,
      boolean active,
      boolean enabled,
      long priority) {}
}
