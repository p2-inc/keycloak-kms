# keycloak-kms — Agent Context

## What this extension does

Replaces Keycloak's realm key providers with ones whose private material the database never holds.
Stock Keycloak keeps a PEM private key in `COMPONENT_CONFIG.privateKey` and base64url secrets in
`secret`; this stores KMS ciphertext instead, or — in native mode — nothing but an ARN.

Two modes:

- **Envelope** (default, supported): key material encrypted under one symmetric CMK, ciphertext in
  component config, signing in process at memory speed.
- **Native** (experimental): non-extractable asymmetric CMK, one `kms:Sign` per token.

## Architecture

```
Keycloak `keys` SPI                              extension `kms` SPI
  kms-rsa-generated      ──encrypt/decrypt──▶      KmsProvider ──▶ AwsKmsProvider  (SigV4 + JDK HttpClient)
  kms-rsa-enc-generated                                        └─▶ LocalKmsProvider (AES-GCM, dev only)
  kms-hmac-generated
  kms-aes-generated
  kms-ec-native          ──sign/publicKey───▶
  kms-rsa-native

KmsResource  /realms/{realm}/kms/{status,migrate,rotate}
KmsBootstrap new-realm installer + startup sweep, both opt-in
```

### Key classes

| Class | Role |
|---|---|
| `spi/KmsProvider` | The backend abstraction. `encrypt`/`decrypt` with an `EncryptionContext`, plus `sign`/`publicKey` for native. |
| `spi/EncryptionContext` | AAD binding a ciphertext to `{app, realm, kid, keyType}`. KMS enforces it. |
| `keys/WrappedMaterial` | The `kms://v1/<base64url>` codec. The `v1` makes a format change a legible error. |
| `keys/KeyCache` | Unwrapped material, keyed by **content** (a digest of the ciphertext), not by component id. |
| `keys/AbstractKmsKeyProviderFactory` | Generation, `seal()` with read-back verification, and the carry-forward guard. |
| `aws/KmsApi` | The KMS wire protocol: six operations, retry taxonomy, error messages that name the IAM permission at fault. |
| `aws/credentials/*` | Six credential sources and the chain that picks one and sticks to it. |
| `migration/KmsKeyMigrator` | Reads stock material, preserves the kid, seals, verifies, deactivates the legacy provider. |
| `keys/nativemode/KmsJcaProvider` | The JCA seam. Registered last; accepts only `KmsPrivateKey`. |

## Things that are the way they are for a reason

**The encryption context is mandatory.** The `serverless` implementation this came from used
AES-GCM with no AAD, so any wrapped value decrypted anywhere the KEK was present. With per-realm
tenancy in one database that is a real weakness. `LocalKmsProvider` enforces it too — a dev backend
that ignored it would let every isolation test pass while the property went untested.

**`KeyCache` is keyed by content.** The alternative — key on component id, invalidate on an update
event — has a window where a rotated key keeps signing with the material it replaced, and depends
on an event arriving. Keycloak publishes no component-lifecycle event anyway.

**`seal()` reads back before persisting.** It catches the failures that actually happen: a context
assembled differently on the write and read paths, a per-component key id the decrypt path drops.
Each produces a key that works until the next restart and then locks a realm out.

**`validateConfiguration` carries stored material forward.** The admin API's component
representation is built from *declared* config properties, so `wrappedMaterial` and `kid` are not
in it. A console save round-trips without them, and stock Keycloak's answer to missing material is
to regenerate — which would mint a new kid and invalidate every live token.

**Migration deactivates, never deletes.** While the legacy component exists, re-enabling it is a
complete rollback.

**Nothing creates or deletes asymmetric CMKs.** See `docs/native-mode.md`.

**No runtime dependencies.** AWS is reached with hand-rolled SigV4 over the JDK HTTP client. The
AWS SDK would add megabytes to `providers/` and a Jackson version to argue with, to save a few
hundred lines.

## Bugs found by testing, worth not reintroducing

- **Keycloak maps PS256 to `"SHA256withRSAandMGF1"`, not `"RSASSA-PSS"`.** `KmsJcaProvider`
  registers both. Routing tests derive the JCA name from `JavaAlgorithm` rather than hard-coding it
  — an earlier version hard-coded the wrong one and the tests passed while PSS was broken.
- **`SelfSignedCertMinter` must sign with the algorithm it declares.** It once declared PKCS#1 in
  the `AlgorithmIdentifier` while signing with PSS, producing a certificate nothing could verify.
  `certificateAlgorithm()` maps PSS to PKCS#1 for both.
- **The admin components API is not a view of stored config.** Assert through
  `GET /realms/{realm}/kms/status`, which reads the model.
- **Realm import JSON cannot carry `_comment` keys.** Keycloak's parser is strict and startup
  fails.
- **Direct grant needs a complete user profile.** Without email/first/last, Keycloak's declarative
  user profile adds `VERIFY_PROFILE` and the grant fails with "Account is not fully set up".

## Build

```bash
mvn test      # unit only, no Docker
mvn verify    # + LocalStack and Keycloak integration suites
make dev      # Keycloak + LocalStack, two realms, nothing talks to AWS
```

SigV4 golden vectors come from botocore (`src/test/resources/regenerate-sigv4-vectors.sh`). If a
signature test fails, regenerating the vectors deletes the test — regenerate only when adding a new
request shape.

## Phase Two conventions used

- `@AutoService` for SPI discovery, `@JBossLog` for logging, `representation` for JAX-RS DTOs
- `AbstractAdminResource` / `BaseRealmResourceProvider` / `CorsResource` copied from
  `keycloak-magic-link` — the established admin-resource shape across these extensions
- Every Keycloak dependency `provided`
- Google Java Format via `fmt-maven-plugin`, checked in CI
- `testcontainers-keycloak` + REST-Assured for integration tests

## Sibling projects

- `bridge-extensions` — the other Phase Two extensions. `keycloak-transactional-email` is the
  closest model (custom SPI, multiple backends, hand-rolled SigV4 for SES).
- `serverless` — where the envelope design came from (§8.2 Tier A, decisions D-014/D-016). It keeps
  its own `WrappedKeyProviderFactory`; the two are deliberately independent.
