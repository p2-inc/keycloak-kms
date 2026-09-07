package io.phasetwo.keycloak.kms.spi;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Additional authenticated data bound to a ciphertext.
 *
 * <p>AWS KMS authenticates (but does not encrypt) this map, and requires the same map at decrypt
 * time. That turns a convention into an enforced property: a {@code wrappedMaterial} value copied
 * out of realm A's component config and pasted into realm B's will not decrypt, because the realm
 * id it was sealed against no longer matches. The same holds for a value relabelled with a
 * different kid or key type.
 *
 * <p>The context is mandatory rather than optional, and every backend must enforce it. An envelope
 * with no AAD decrypts anywhere the KEK is present, which in a shared database with per-realm
 * administrators is a real weakness — one that no test notices unless the property is enforced on
 * the only backend the tests can reach.
 *
 * <p>The context is also expressible in a KMS key policy, which is how an operator makes it a
 * KMS-side guarantee rather than something our code promises:
 *
 * <pre>{@code "Condition": {"StringEquals": {"kms:EncryptionContext:app": "keycloak"}}}</pre>
 */
public final class EncryptionContext {

  /** Marks every ciphertext this extension writes, so a key policy can require it. */
  public static final String APP = "keycloak";

  public static final String KEY_APP = "app";
  public static final String KEY_REALM = "realm";
  public static final String KEY_KID = "kid";
  public static final String KEY_TYPE = "keyType";

  private final Map<String, String> entries;

  private EncryptionContext(Map<String, String> entries) {
    this.entries = Collections.unmodifiableMap(entries);
  }

  /**
   * The context for one realm key.
   *
   * @param realmId the realm's id (not its name — names are mutable, ids are not)
   * @param kid the key id published in JWKS
   * @param keyType {@code RSA}, {@code RSA_ENC}, {@code EC}, {@code HMAC} or {@code AES}
   */
  public static EncryptionContext forKey(String realmId, String kid, String keyType) {
    Objects.requireNonNull(realmId, "realmId");
    Objects.requireNonNull(kid, "kid");
    Objects.requireNonNull(keyType, "keyType");
    Map<String, String> m = new LinkedHashMap<>();
    m.put(KEY_APP, APP);
    m.put(KEY_REALM, realmId);
    m.put(KEY_KID, kid);
    m.put(KEY_TYPE, keyType);
    return new EncryptionContext(m);
  }

  /** An arbitrary context. Used by tests and by backends that round-trip a stored context. */
  public static EncryptionContext of(Map<String, String> entries) {
    return new EncryptionContext(new LinkedHashMap<>(entries));
  }

  public Map<String, String> asMap() {
    return entries;
  }

  public String realmId() {
    return entries.get(KEY_REALM);
  }

  public String kid() {
    return entries.get(KEY_KID);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof EncryptionContext other && entries.equals(other.entries);
  }

  @Override
  public int hashCode() {
    return entries.hashCode();
  }

  /** Safe to log: contains no secret material, only identifiers. */
  @Override
  public String toString() {
    return entries.toString();
  }
}
