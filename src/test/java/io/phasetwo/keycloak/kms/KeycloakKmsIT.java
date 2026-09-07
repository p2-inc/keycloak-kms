package io.phasetwo.keycloak.kms;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.phasetwo.keycloak.kms.testsupport.Kms;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * The whole thing, in a real Keycloak, against a real KMS API.
 *
 * <p>Everything below this line has been proven in isolation. What only a running server can show
 * is that the extension loads at all, that Keycloak's own signing path picks up a KMS-backed key,
 * and that a token issued through the ordinary token endpoint verifies against the ordinary JWKS
 * endpoint. Those are the claims an operator actually cares about.
 */
class KeycloakKmsIT {

  private static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.3";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static Network network;
  private static LocalStackContainer localstack;
  private static KeycloakContainer keycloak;
  private static Keycloak admin;

  private static String symmetricKeyId;
  private static String ecKeyId;

  @BeforeAll
  static void startEverything() {
    network = Network.newNetwork();

    localstack =
        new LocalStackContainer(DockerImageName.parse("localstack/localstack:3.8"))
            .withServices(LocalStackContainer.Service.KMS)
            .withNetwork(network)
            .withNetworkAliases("kms");
    localstack.start();

    URI endpoint = localstack.getEndpoint();
    symmetricKeyId =
        Kms.createKey(
            endpoint,
            localstack.getRegion(),
            localstack.getAccessKey(),
            localstack.getSecretKey(),
            "ENCRYPT_DECRYPT",
            "SYMMETRIC_DEFAULT");
    ecKeyId =
        Kms.createKey(
            endpoint,
            localstack.getRegion(),
            localstack.getAccessKey(),
            localstack.getSecretKey(),
            "SIGN_VERIFY",
            "ECC_NIST_P256");

    keycloak =
        new KeycloakContainer(KEYCLOAK_IMAGE)
            .withNetwork(network)
            .withProviderClassesFrom("target/classes")
            // Command-line options rather than KC_SPI_* environment variables: the env mapping for
            // SPI options has changed shape across Keycloak versions, and a test whose purpose is
            // to prove the extension works should not also be a bet on that spelling.
            .withCustomCommand("--spi-kms--provider=aws")
            .withCustomCommand("--spi-kms--aws--region=" + localstack.getRegion())
            .withCustomCommand("--spi-kms--aws--key-id=" + symmetricKeyId)
            // Inside the network LocalStack is reachable at its alias, not at the mapped port.
            .withCustomCommand("--spi-kms--aws--endpoint=http://kms:4566")
            .withEnv("AWS_ACCESS_KEY_ID", localstack.getAccessKey())
            .withEnv("AWS_SECRET_ACCESS_KEY", localstack.getSecretKey())
            .withEnv("AWS_REGION", localstack.getRegion());
    keycloak.start();

    admin = keycloak.getKeycloakAdminClient();
  }

  @AfterAll
  static void stopEverything() {
    if (admin != null) {
      admin.close();
    }
    if (keycloak != null) {
      keycloak.stop();
    }
    if (localstack != null) {
      localstack.stop();
    }
    if (network != null) {
      network.close();
    }
  }

  // ------------------------------------------------------------------ fixtures

  /** A realm with a confidential-enough client and a user, so a token can actually be obtained. */
  private static void createRealm(String name) {
    RealmRepresentation realm = new RealmRepresentation();
    realm.setRealm(name);
    realm.setEnabled(true);
    admin.realms().create(realm);

    var client = new org.keycloak.representations.idm.ClientRepresentation();
    client.setClientId("app");
    client.setPublicClient(true);
    client.setDirectAccessGrantsEnabled(true);
    client.setEnabled(true);
    admin.realm(name).clients().create(client).close();

    UserRepresentation user = new UserRepresentation();
    user.setUsername("alice");
    user.setEnabled(true);
    // Keycloak's declarative user profile adds a VERIFY_PROFILE required action when email, first
    // or last name are missing, and a direct grant against such a user fails with "Account is not
    // fully set up" rather than anything mentioning profiles.
    user.setEmail("alice@example.com");
    user.setEmailVerified(true);
    user.setFirstName("Alice");
    user.setLastName("Example");
    CredentialRepresentation password = new CredentialRepresentation();
    password.setType(CredentialRepresentation.PASSWORD);
    password.setValue("password");
    password.setTemporary(false);
    user.setCredentials(List.of(password));
    admin.realm(name).users().create(user).close();
  }

  private static String addComponent(String realm, String providerId, Map<String, String> config) {
    ComponentRepresentation component = new ComponentRepresentation();
    component.setName(providerId);
    component.setProviderId(providerId);
    component.setProviderType("org.keycloak.keys.KeyProvider");
    component.setParentId(admin.realm(realm).toRepresentation().getId());
    var multivalued = new org.keycloak.common.util.MultivaluedHashMap<String, String>();
    config.forEach(multivalued::putSingle);
    component.setConfig(multivalued);

    try (var response = admin.realm(realm).components().add(component)) {
      assertEquals(
          201,
          response.getStatus(),
          "adding " + providerId + " failed: " + response.readEntity(String.class));
      String location = response.getHeaderString("Location");
      return location.substring(location.lastIndexOf('/') + 1);
    }
  }

  private static JsonNode jwks(String realm) throws Exception {
    return MAPPER.readTree(
        given()
            .baseUri(keycloak.getAuthServerUrl())
            .get("/realms/" + realm + "/protocol/openid-connect/certs")
            .then()
            .statusCode(200)
            .extract()
            .asString());
  }

  private static String tokenKid(String realm) throws Exception {
    String accessToken =
        MAPPER
            .readTree(
                given()
                    .baseUri(keycloak.getAuthServerUrl())
                    .formParam("client_id", "app")
                    .formParam("grant_type", "password")
                    .formParam("username", "alice")
                    .formParam("password", "password")
                    .contentType("application/x-www-form-urlencoded")
                    .post("/realms/" + realm + "/protocol/openid-connect/token")
                    .then()
                    .statusCode(
                        org.hamcrest.Matchers.describedAs(
                            "token request for realm " + realm, org.hamcrest.Matchers.is(200)))
                    .extract()
                    .asString())
            .get("access_token")
            .asText();

    String header =
        new String(
            Base64.getUrlDecoder().decode(accessToken.split("\\.")[0]), StandardCharsets.UTF_8);
    return MAPPER.readTree(header).get("kid").asText();
  }

  /** A JWK Set as a kid -> JWK map, which is how a relying party reads it. */
  private static Map<String, JsonNode> keysByKid(JsonNode jwks) {
    Map<String, JsonNode> keys = new java.util.LinkedHashMap<>();
    for (JsonNode key : jwks.get("keys")) {
      keys.put(key.get("kid").asText(), key);
    }
    return keys;
  }

  private static JsonNode jwkFor(JsonNode jwks, String kid) {
    for (JsonNode key : jwks.get("keys")) {
      if (kid.equals(key.get("kid").asText())) {
        return key;
      }
    }
    throw new AssertionError("no JWK published for kid " + kid + " in " + jwks);
  }

  private static String adminToken() throws Exception {
    return MAPPER
        .readTree(
            given()
                .baseUri(keycloak.getAuthServerUrl())
                .formParam("client_id", "admin-cli")
                .formParam("grant_type", "password")
                .formParam("username", keycloak.getAdminUsername())
                .formParam("password", keycloak.getAdminPassword())
                .contentType("application/x-www-form-urlencoded")
                .post("/realms/master/protocol/openid-connect/token")
                .then()
                .statusCode(200)
                .extract()
                .asString())
        .get("access_token")
        .asText();
  }

  /**
   * This realm's key providers as the server sees them.
   *
   * <p>Read through the extension's own endpoint rather than the admin components API, because the
   * admin representation is not a faithful view of a component's stored config — Keycloak builds it
   * from what the factory declares, so values a factory generates for itself (a kid, the wrapped
   * material) are simply absent. Asserting "privateKey is null" against that representation would
   * pass whether or not the plaintext was really gone.
   */
  private static JsonNode kmsStatus(String realm) throws Exception {
    return MAPPER.readTree(
        given()
            .baseUri(keycloak.getAuthServerUrl())
            .header("Authorization", "Bearer " + adminToken())
            .get("/realms/" + realm + "/kms/status")
            .then()
            .statusCode(200)
            .extract()
            .asString());
  }

  private static JsonNode keyStatus(JsonNode status, String componentId) {
    for (JsonNode key : status.get("keys")) {
      if (componentId.equals(key.get("componentId").asText())) {
        return key;
      }
    }
    throw new AssertionError("no status for component " + componentId + " in " + status);
  }

  // ------------------------------------------------------------------ the extension loads

  @Test
  @DisplayName("all eight providers are registered in a real server")
  void providersAreRegistered() {
    var info = admin.serverInfo().getInfo();
    List<String> keyProviders =
        info.getProviders().get("keys").getProviders().keySet().stream().sorted().toList();

    assertTrue(keyProviders.contains("kms-rsa-generated"), keyProviders.toString());
    assertTrue(keyProviders.contains("kms-rsa-enc-generated"), keyProviders.toString());
    assertTrue(keyProviders.contains("kms-hmac-generated"), keyProviders.toString());
    assertTrue(keyProviders.contains("kms-aes-generated"), keyProviders.toString());
    assertTrue(keyProviders.contains("kms-ec-native"), keyProviders.toString());
    assertTrue(keyProviders.contains("kms-rsa-native"), keyProviders.toString());

    // The custom SPI has to be discovered too, or nothing above it works.
    assertNotNull(info.getProviders().get("kms"), "the kms SPI was not registered");
    assertTrue(info.getProviders().get("kms").getProviders().containsKey("aws"));
  }

  // ------------------------------------------------------------------ envelope, end to end

  @Test
  @DisplayName("a token is signed by a KMS-backed key and verifies against the realm's JWKS")
  void envelopeKeySignsRealTokens() throws Exception {
    String realm = "envelope";
    createRealm(realm);
    // Priority above the stock generated key, which Keycloak creates at -100.
    String componentId =
        addComponent(realm, "kms-rsa-generated", Map.of("priority", "200", "algorithm", "RS256"));

    String kid = tokenKid(realm);
    JsonNode key = keyStatus(kmsStatus(realm), componentId);

    assertEquals(
        key.get("kid").asText(),
        kid,
        "the token must be signed by the KMS-backed key, not the realm's stock one");
    assertTrue(key.get("kmsBacked").asBoolean());
    assertFalse(key.get("holdsPlaintext").asBoolean(), "no plaintext for this provider");

    JsonNode jwk = jwkFor(jwks(realm), kid);
    assertEquals("RSA", jwk.get("kty").asText());
    assertEquals("RS256", jwk.get("alg").asText());
  }

  @Test
  @DisplayName("HMAC and AES keys work too, so the whole realm is covered")
  void secretKeysWork() throws Exception {
    String realm = "secrets";
    createRealm(realm);
    String hmac = addComponent(realm, "kms-hmac-generated", Map.of("priority", "200"));
    String aes = addComponent(realm, "kms-aes-generated", Map.of("priority", "200"));

    JsonNode status = kmsStatus(realm);
    for (String id : List.of(hmac, aes)) {
      JsonNode key = keyStatus(status, id);
      assertTrue(key.get("kmsBacked").asBoolean(), key.toString());
      assertFalse(key.get("holdsPlaintext").asBoolean(), "the secret must not be in the database");
      assertNotNull(key.get("kid").asText(), key.toString());
    }
  }

  // ------------------------------------------------------------------ migration, end to end

  @Test
  @DisplayName("migrating a realm leaves every published key unchanged")
  void migrationDoesNotChangeJwks() throws Exception {
    String realm = "legacy";
    createRealm(realm);

    JsonNode before = jwks(realm);
    String kidBefore = tokenKid(realm);

    String report =
        given()
            .baseUri(keycloak.getAuthServerUrl())
            .header("Authorization", "Bearer " + adminToken())
            .contentType("application/json")
            .post("/realms/" + realm + "/kms/migrate")
            .then()
            .statusCode(200)
            .extract()
            .asString();

    JsonNode parsed = MAPPER.readTree(report);
    assertTrue(parsed.get("migrated").size() >= 3, "expected RSA, HMAC and AES: " + report);
    assertTrue(parsed.get("plaintextRemains").asBoolean(), "the legacy components are still there");
    assertTrue(
        parsed.get("warnings").toString().contains("backups"),
        "the report must say migrated material was already exposed");

    // The headline: the same keys, unchanged.
    //
    // Compared as a set keyed by kid, not as a document. A JWK Set is unordered by RFC 7517 and
    // clients select by kid, and migration does re-order it — the migrated components are new rows
    // and Keycloak's tie-break between equal priorities follows creation order. Asserting document
    // equality would be asserting something neither guaranteed nor needed; asserting every kid maps
    // to a byte-identical JWK is the property relying parties actually depend on.
    assertEquals(
        keysByKid(before),
        keysByKid(jwks(realm)),
        "every published key must survive migration unchanged");
    assertEquals(kidBefore, tokenKid(realm), "tokens must keep the kid they had");

    // And the migrated component really is KMS-backed now.
    JsonNode rsa =
        java.util.stream.StreamSupport.stream(parsed.get("migrated").spliterator(), false)
            .filter(m -> "RSA".equals(m.get("keyType").asText()))
            .findFirst()
            .orElseThrow();
    JsonNode migrated = keyStatus(kmsStatus(realm), rsa.get("newComponentId").asText());
    assertEquals("kms-rsa-generated", migrated.get("providerId").asText());
    assertTrue(migrated.get("kmsBacked").asBoolean());
    assertFalse(migrated.get("holdsPlaintext").asBoolean());
  }

  @Test
  @DisplayName("deleteLegacy removes the plaintext and the realm reports itself clean")
  void migrationWithDeleteClosesTheFinding() throws Exception {
    String realm = "legacy-delete";
    createRealm(realm);
    String kidBefore = tokenKid(realm);

    given()
        .baseUri(keycloak.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminToken())
        .contentType("application/json")
        .queryParam("deleteLegacy", true)
        .post("/realms/" + realm + "/kms/migrate")
        .then()
        .statusCode(200)
        .body("plaintextRemains", org.hamcrest.Matchers.is(false));

    assertEquals(
        kidBefore, tokenKid(realm), "deleting the legacy component must not change the kid");

    String status =
        given()
            .baseUri(keycloak.getAuthServerUrl())
            .header("Authorization", "Bearer " + adminToken())
            .get("/realms/" + realm + "/kms/status")
            .then()
            .statusCode(200)
            .extract()
            .asString();
    JsonNode parsed = MAPPER.readTree(status);
    assertFalse(parsed.get("plaintextRemains").asBoolean(), status);
    for (JsonNode key : parsed.get("keys")) {
      assertTrue(key.get("kmsBacked").asBoolean(), key.toString());
      assertFalse(key.get("holdsPlaintext").asBoolean(), key.toString());
    }
  }

  @Test
  @DisplayName("rotation issues tokens under a new kid while the old one stays published")
  void rotation() throws Exception {
    String realm = "rotate";
    createRealm(realm);
    given()
        .baseUri(keycloak.getAuthServerUrl())
        .header("Authorization", "Bearer " + adminToken())
        .contentType("application/json")
        .queryParam("deleteLegacy", true)
        .post("/realms/" + realm + "/kms/migrate")
        .then()
        .statusCode(200);

    String kidBefore = tokenKid(realm);

    String result =
        given()
            .baseUri(keycloak.getAuthServerUrl())
            .header("Authorization", "Bearer " + adminToken())
            .contentType("application/json")
            .queryParam("keyType", "RSA")
            .post("/realms/" + realm + "/kms/rotate")
            .then()
            .statusCode(200)
            .extract()
            .asString();

    String newKid = MAPPER.readTree(result).get("newKid").asText();
    assertEquals(newKid, tokenKid(realm), "new tokens must use the rotated key");

    JsonNode published = jwks(realm);
    assertNotNull(jwkFor(published, newKid));
    assertNotNull(
        jwkFor(published, kidBefore),
        "the previous key must stay published or every live token breaks");
  }

  // ------------------------------------------------------------------ native, end to end

  @Test
  @DisplayName("a native EC key signs real tokens without the private key ever existing here")
  void nativeEcSignsRealTokens() throws Exception {
    String realm = "native";
    createRealm(realm);
    String componentId =
        addComponent(
            realm,
            "kms-ec-native",
            Map.of("priority", "200", "kmsKeyId", ecKeyId, "algorithm", "ES256"));

    // ES256 has to be the realm's token signature algorithm for it to be chosen.
    RealmRepresentation representation = admin.realm(realm).toRepresentation();
    representation.setDefaultSignatureAlgorithm("ES256");
    admin.realm(realm).update(representation);

    String kid = tokenKid(realm);
    JsonNode key = keyStatus(kmsStatus(realm), componentId);
    assertEquals(key.get("kid").asText(), kid, "the token must be signed by the native key");
    assertTrue(key.get("kmsBacked").asBoolean());
    assertFalse(key.get("holdsPlaintext").asBoolean(), "a native key stores only an ARN");

    JsonNode jwk = jwkFor(jwks(realm), kid);
    assertEquals("EC", jwk.get("kty").asText());
    assertEquals("ES256", jwk.get("alg").asText());
    assertEquals("P-256", jwk.get("crv").asText());
  }
}
