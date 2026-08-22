package io.phasetwo.keycloak.kms.bootstrap;

import io.phasetwo.keycloak.kms.KmsConfig;
import io.phasetwo.keycloak.kms.keys.envelope.KmsAesKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsHmacKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaEncKeyProviderFactory;
import io.phasetwo.keycloak.kms.keys.envelope.KmsRsaKeyProviderFactory;
import io.phasetwo.keycloak.kms.migration.KmsKeyMigrator;
import io.phasetwo.keycloak.kms.representation.MigrationReport;
import java.util.List;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;

/**
 * Two optional lifecycle hooks, both off by default.
 *
 * <ul>
 *   <li><strong>New realms.</strong> With {@code --spi-kms--default-for-new-realms=true}, a realm
 *       created through the console or the admin API gets KMS-backed key providers instead of the
 *       stock ones — so an organisation that has decided keys belong in the KMS does not have to
 *       remember to migrate every realm anyone creates.
 *   <li><strong>Startup sweep.</strong> With {@code --spi-kms--migrate-on-startup=true}, every
 *       realm is migrated at boot. Off by default: a sweep across every realm is a lot of KMS calls
 *       and a lot of writes to perform without being asked, and the per-realm REST endpoint is the
 *       supported path.
 * </ul>
 *
 * <p>Invoked from {@code KmsResourceProviderFactory.postInit}, which is simply the hook this
 * extension already has. A dedicated SPI would be more decorative and no more capable.
 */
@JBossLog
public final class KmsBootstrap {

  /** The stock providers a new realm is created with, and what replaces each. */
  private static final List<String[]> DEFAULTS =
      List.of(
          new String[] {"rsa-generated", KmsRsaKeyProviderFactory.ID},
          new String[] {"rsa-enc-generated", KmsRsaEncKeyProviderFactory.ID},
          new String[] {"hmac-generated", KmsHmacKeyProviderFactory.ID},
          new String[] {"aes-generated", KmsAesKeyProviderFactory.ID});

  private KmsBootstrap() {}

  public static void install(KeycloakSessionFactory factory) {
    if (KmsConfig.defaultForNewRealms()) {
      factory.register(newRealmListener());
      log.info(
          "kms: new realms will be created with KMS-backed key providers"
              + " (--spi-kms--default-for-new-realms=true)");
    }
    if (KmsConfig.migrateOnStartup()) {
      runStartupSweep(factory);
    }
  }

  private static ProviderEventListener newRealmListener() {
    return (ProviderEvent event) -> {
      if (event instanceof RealmModel.RealmPostCreateEvent created) {
        RealmModel realm = created.getCreatedRealm();
        try {
          installDefaults(realm);
        } catch (RuntimeException e) {
          // A realm that exists with stock keys is recoverable; failing the creation is not what an
          // administrator wants from an optional convenience. Say exactly how to finish the job.
          log.errorf(
              e,
              "kms: could not install KMS key providers on new realm '%s'. It has Keycloak's"
                  + " default providers, whose key material is in the database. Fix the cause, then"
                  + " run: POST /realms/%s/kms/migrate",
              realm.getName(),
              realm.getName());
        }
      }
    };
  }

  /**
   * Swap a brand-new realm's stock key providers for KMS-backed ones.
   *
   * <p>Runs after Keycloak has created its defaults, so it deletes what it replaces. Deleting is
   * safe here in a way it is not during migration: these keys are seconds old, have signed nothing,
   * and no relying party has ever seen them.
   */
  static void installDefaults(RealmModel realm) {
    List<ComponentModel> existing =
        realm.getComponentsStream(realm.getId(), KeyProvider.class.getName()).toList();

    for (String[] pair : DEFAULTS) {
      String stockId = pair[0];
      String kmsId = pair[1];

      List<ComponentModel> stock =
          existing.stream().filter(c -> stockId.equals(c.getProviderId())).toList();
      if (stock.isEmpty()) {
        continue;
      }

      ComponentModel model = new ComponentModel();
      model.setName(kmsId);
      model.setParentId(realm.getId());
      model.setProviderId(kmsId);
      model.setProviderType(KeyProvider.class.getName());
      MultivaluedHashMap<String, String> config = new MultivaluedHashMap<>();
      config.putSingle(
          Attributes.PRIORITY_KEY, String.valueOf(stock.get(0).get(Attributes.PRIORITY_KEY, 100L)));
      model.setConfig(config);
      realm.addComponentModel(model);

      stock.forEach(realm::removeComponent);
    }

    log.infof(
        "kms: realm '%s' created with KMS-backed key providers; no key material was written to the"
            + " database",
        realm.getName());
  }

  /** Migrate every realm at boot. Opt-in, and loud about what it did. */
  private static void runStartupSweep(KeycloakSessionFactory factory) {
    log.warn(
        "kms: --spi-kms--migrate-on-startup=true — migrating every realm's keys into the KMS now."
            + " Legacy providers will be deactivated, not deleted; each realm's log line says what"
            + " is left to remove.");
    try {
      KeycloakModelUtils.runJobInTransaction(
          factory,
          session -> {
            if (!KmsKeyMigrator.extensionIsUsable(session)) {
              log.error(
                  "kms: no KMS key provider factories registered; skipping the startup sweep");
              return;
            }
            KmsKeyMigrator migrator = new KmsKeyMigrator(session);
            session
                .realms()
                .getRealmsStream()
                .forEach(
                    realm -> {
                      MigrationReport report = migrator.migrate(realm, false);
                      if (!report.migrated().isEmpty() || report.plaintextRemains()) {
                        log.infof(
                            "kms: startup sweep — realm '%s': %d migrated, %d skipped, plaintext"
                                + " remains: %s",
                            realm.getName(),
                            report.migrated().size(),
                            report.skipped().size(),
                            report.plaintextRemains());
                      }
                    });
          });
    } catch (RuntimeException e) {
      // Do not take the server down for this. The realms that migrated are migrated, and an
      // operator who asked for a sweep needs the server up to finish the rest by hand.
      log.error("kms: the startup migration sweep failed part-way through", e);
    }
  }
}
