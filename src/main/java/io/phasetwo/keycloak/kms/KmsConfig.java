package io.phasetwo.keycloak.kms;

import org.keycloak.Config;

/**
 * Settings that belong to the extension as a whole rather than to one KMS backend or one key
 * provider.
 *
 * <p>Read from the {@code kms} SPI scope, so they are set once for the server:
 *
 * <pre>{@code
 * --spi-kms--cache-ttl-seconds=300
 * --spi-kms--default-for-new-realms=true
 * --spi-kms--migrate-on-startup=false
 * }</pre>
 */
public final class KmsConfig {

  public static final long DEFAULT_CACHE_TTL_SECONDS = 300;

  private KmsConfig() {}

  private static Config.Scope scope() {
    return Config.scope("kms");
  }

  /**
   * How long an unwrapped key stays in memory. Zero disables caching entirely, which turns every
   * signature into a KMS call — correct for the truly paranoid and ruinous for everyone else.
   */
  public static long cacheTtlMillis() {
    return scope().getLong("cacheTtlSeconds", DEFAULT_CACHE_TTL_SECONDS) * 1000L;
  }

  /** Install KMS-backed key providers on newly created realms instead of the stock ones. */
  public static boolean defaultForNewRealms() {
    return scope().getBoolean("defaultForNewRealms", false);
  }

  /** Sweep every realm at startup, migrating stock providers. Off by default. */
  public static boolean migrateOnStartup() {
    return scope().getBoolean("migrateOnStartup", false);
  }

  /** Which backend is selected, for log lines that want to name it. */
  public static String backendId() {
    return scope().get("provider");
  }
}
