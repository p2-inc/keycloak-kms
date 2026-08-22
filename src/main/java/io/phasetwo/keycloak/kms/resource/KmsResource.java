package io.phasetwo.keycloak.kms.resource;

import io.phasetwo.keycloak.kms.keys.KmsKeyType;
import io.phasetwo.keycloak.kms.migration.KmsKeyMigrator;
import io.phasetwo.keycloak.kms.representation.MigrationReport;
import io.phasetwo.keycloak.kms.representation.RealmKmsStatus;
import io.phasetwo.keycloak.kms.representation.RotationResult;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import java.util.Arrays;
import java.util.Locale;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.models.KeycloakSession;

/**
 * Realm-scoped operations, at {@code /realms/{realm}/kms}.
 *
 * <p>Three endpoints, matching the three questions an operator actually has: what is the state of
 * this realm's keys, move them into the KMS, and give me material that has never been in the
 * database.
 */
@JBossLog
public class KmsResource extends AbstractAdminResource {

  public KmsResource(KeycloakSession session) {
    super(session);
  }

  /**
   * What this realm's key providers look like, including whether any plaintext is left.
   *
   * <p>Read-only, so {@code view-realm} is enough — and being able to check without holding {@code
   * manage-realm} is the point, since this is the query an auditor wants to run.
   */
  @GET
  @Path("status")
  @Produces(MediaType.APPLICATION_JSON)
  public RealmKmsStatus status() {
    permissions.realm().requireViewRealm();
    return new KmsKeyMigrator(session).status(realm);
  }

  /**
   * Move every migratable key in this realm into the KMS, preserving each kid.
   *
   * @param deleteLegacy delete the legacy providers rather than deactivating them. Defaults to
   *     false: a deactivated component is a complete rollback, a deleted one is not.
   */
  @POST
  @Path("migrate")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public MigrationReport migrate(
      @QueryParam("deleteLegacy") @DefaultValue("false") boolean deleteLegacy) {
    permissions.realm().requireManageRealm();
    log.infof(
        "kms: migrating realm '%s' at the request of %s (deleteLegacy=%s)",
        realm.getName(), auth.getUser().getUsername(), deleteLegacy);
    MigrationReport report = new KmsKeyMigrator(session).migrate(realm, deleteLegacy);
    adminEvent
        .operation(org.keycloak.events.admin.OperationType.UPDATE)
        .resourcePath(session.getContext().getUri())
        .representation(report)
        .success();
    return report;
  }

  /**
   * Generate a fresh KMS-held key of one type and promote it above the existing ones.
   *
   * <p>The follow-up to migration, and the only way to get material that has never been at rest in
   * the database. Standard rotation semantics: previous keys stay published until the operator
   * retires them.
   */
  @POST
  @Path("rotate")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  public RotationResult rotate(@QueryParam("keyType") @DefaultValue("RSA") String keyType) {
    permissions.realm().requireManageRealm();
    KmsKeyType type = parseKeyType(keyType);
    log.infof(
        "kms: rotating %s in realm '%s' at the request of %s",
        type, realm.getName(), auth.getUser().getUsername());
    RotationResult result = new KmsKeyMigrator(session).rotate(realm, type);
    adminEvent
        .operation(org.keycloak.events.admin.OperationType.CREATE)
        .resourcePath(session.getContext().getUri())
        .representation(result)
        .success();
    return result;
  }

  private static KmsKeyType parseKeyType(String value) {
    try {
      KmsKeyType type = KmsKeyType.valueOf(value.toUpperCase(Locale.ROOT));
      if (type == KmsKeyType.EC) {
        throw new BadRequestException(
            "EC keys are native-mode only in this version. Native providers are created by hand"
                + " with an asymmetric CMK; there is nothing to rotate into automatically.");
      }
      return type;
    } catch (IllegalArgumentException e) {
      throw new BadRequestException(
          "unknown keyType '"
              + value
              + "'. Expected one of "
              + Arrays.stream(KmsKeyType.values())
                  .filter(t -> t != KmsKeyType.EC)
                  .map(Enum::name)
                  .toList());
    }
  }
}
