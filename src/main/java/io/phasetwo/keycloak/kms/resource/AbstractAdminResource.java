package io.phasetwo.keycloak.kms.resource;

import jakarta.ws.rs.*;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.RealmManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.fgap.AdminPermissions;

/**
 * Bearer-token admin authentication for a realm-scoped REST resource.
 *
 * <p>Copied from {@code keycloak-magic-link}, which is the established shape for admin resources
 * across these extensions. Deliberately not reinvented: it resolves the realm from the token's
 * issuer, authenticates against that realm, and builds the permission evaluator the fine-grained
 * admin model expects — all places where a subtly different implementation would be a subtly
 * different authorisation boundary.
 */
@JBossLog
public abstract class AbstractAdminResource {

  protected final ClientConnection connection;
  protected final HttpHeaders headers;
  protected final KeycloakSession session;
  protected final RealmModel realm;

  protected AdminAuth auth;
  protected AdminEventBuilder adminEvent;
  protected AdminPermissionEvaluator permissions;
  protected EventBuilder event;

  protected AbstractAdminResource(KeycloakSession session) {
    this.session = session;
    this.realm = session.getContext().getRealm();
    this.headers = session.getContext().getRequestHeaders();
    this.connection = session.getContext().getConnection();
  }

  public void setup() {
    setupAuth();
    setupEvents();
    setupPermissions();
    setupCors();
  }

  private void setupCors() {
    CorsResource.setupCors(session, auth);
  }

  private void setupAuth() {
    auth = authenticateRealmAdminRequest(headers);
  }

  private void setupEvents() {
    adminEvent =
        new AdminEventBuilder(this.realm, auth, session, session.getContext().getConnection())
            .realm(realm);
    event = new EventBuilder(this.realm, session, connection).realm(realm);
  }

  private void setupPermissions() {
    permissions = AdminPermissions.evaluator(session, realm, auth);
  }

  private AdminAuth authenticateRealmAdminRequest(HttpHeaders headers) {
    String tokenString = AppAuthManager.extractAuthorizationHeaderToken(headers);
    if (tokenString == null) throw new NotAuthorizedException("Bearer");
    AccessToken token;
    try {
      JWSInput input = new JWSInput(tokenString);
      token = input.readJsonContent(AccessToken.class);
    } catch (JWSInputException e) {
      throw new NotAuthorizedException("Bearer token format error");
    }
    String realmName = token.getIssuer().substring(token.getIssuer().lastIndexOf('/') + 1);
    RealmManager realmManager = new RealmManager(session);
    RealmModel realm = realmManager.getRealmByName(realmName);
    if (realm == null) {
      throw new NotAuthorizedException("Unknown realm in token");
    }
    session.getContext().setRealm(realm);

    AuthenticationManager.AuthResult authResult =
        new AppAuthManager.BearerTokenAuthenticator(session)
            .setRealm(realm)
            .setConnection(connection)
            .setHeaders(headers)
            .authenticate();

    if (authResult == null) {
      log.debug("Token not valid");
      throw new NotAuthorizedException("Bearer");
    }

    ClientModel client = realm.getClientByClientId(token.getIssuedFor());
    if (client == null) {
      throw new NotFoundException("Could not find client for authorization");
    }

    return new AdminAuth(realm, authResult.getToken(), authResult.getUser(), client);
  }
}
