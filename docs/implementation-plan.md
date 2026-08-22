# Implementation plan — `keycloak-kms`

> Status: **decisions resolved, plan for approval.** §2 records what was decided and what follows
> from it. §11 lists what remains genuinely open.

Companion: [`user-story.md`](user-story.md) — the operator experience this plan delivers.

---

## 1. What we are porting, and what does not port

The mechanism comes from the `serverless` project's §8.2 Tier-A key custody (DECISIONS D-014 Q3,
D-016). Three classes carry the whole idea:

| Source (`serverless`) | Role | Fate in the extension |
|---|---|---|
| `provider/keys/KmsClient.java` | `wrap(byte[]) / unwrap(byte[])` — the entire KMS abstraction | **Ports directly.** Becomes the `kms` SPI, plus an encryption-context parameter and the sign/public-key operations Tier B needs. |
| `provisioning/keys/WrappedKeyGen.java` | Mint RSA+HMAC+AES, wrap under KEK, emit component config; `kms://v1/<b64url>` value format | **Ports, restructured.** Split per key type; the value format is kept verbatim. |
| `provider/keys/WrappedKeyProviderFactory.java` | `KeyProvider` that unwraps once and caches plaintext by `(realmId, kid)` with a TTL | **Ports as the core of envelope mode.** One factory per key type. |
| `provider/keys/LocalKmsClient.java` | AES-GCM under a shared `SERVERLESS_KEK` | **Ports as the `local` dev/test backend.** Not the headline. |

What does **not** port, and why it matters more than the parts that do:

- **Provisioning-time injection.** In `serverless` keys are minted by a control plane and injected
  into the realm representation before import. There is no control plane here. Key generation has to
  happen inside Keycloak, on the `KeyProviderFactory` path, driven by the admin console.
- **A single bundled component.** `serverless` puts RSA + HMAC + AES in one `serverless-wrapped`
  component because a provisioner writes it as a unit. An admin using **Realm settings → Keys →
  Providers** expects to add an RSA provider. One factory per key type, mirroring stock.
- **No migration story at all.** `serverless` realms are born with wrapped keys. Every realm this
  extension meets already has plaintext keys in a database. Migration is the substantial new work
  and the reason anyone installs this.
- **`LocalKmsClient` is not a KMS.** It reads a base64 KEK from an environment variable. Real AWS
  KMS — SigV4, credential chain, encryption context, error taxonomy, quotas — is the bulk of the
  engineering and none of it exists today.
- **Tier B was never built.** §8.2 describes sign-in-KMS as a premium tier; `serverless` shipped
  Tier A only. Everything in §5 below is new design.

Also new: `serverless` never bound ciphertext to a realm. Any `kms://` value decrypts anywhere the
KEK is present. With per-realm tenancy in a shared database that is a real weakness, and AWS KMS
gives us the fix for free (encryption context). Mandatory here, not optional.

---

## 2. Decisions (resolved)

| # | Decision | Consequence |
|---|---|---|
| **D1** | **Both custody modes in v1** — envelope as the default, sign-in-KMS as a per-realm premium option. Mirrors §8.2 Tier A / Tier B exactly. | Two provider families (§4, §5). Roughly 1.5× the build. The JCA-interception spike (§5.1) becomes the first schedule risk. |
| **D2** | **Hand-rolled SigV4**, no AWS SDK. Adapt `AwsSigV4Signer` from `keycloak-transactional-email`. | Jar stays ~80 KB with zero dependencies beyond what Keycloak ships. We own SigV4 and credential-chain correctness; AWS's published signing vectors become unit tests. |
| **D3** | **Define the `kms` SPI**; ship `aws` and `local` backends. | GCP KMS / Azure Key Vault / Vault Transit become community-sized contributions. Costs almost nothing now — the abstraction already exists as `KmsClient`. |
| **D4** | **Elastic License 2.0**, matching every other extension in `bridge-extensions`. | `COPYING` + the ELv2 `<licenses>` block in the POM, as in `keycloak-magic-link`. |
| **D5** | **`serverless` stays independent** — no dependency in either direction. | ~150 lines of envelope logic exist in both places. Accepted: `serverless` keeps zero external dependencies on a Tier-0 signing path, and the two evolve on their own schedules. |
| **D7** | **ES256 leads native mode.** `ECC_NIST_P256` ships first; `kms-rsa-native` follows. | ECC signatures are faster and cheaper inside KMS than RSA, and the certificate/PSS complications are smaller. `kms-ec-native` is the reference native provider; RSA reuses its machinery. |
| **D8** | **Native mode ships marked experimental in v1.** | README, provider help text and startup log all say so. Envelope mode is the supported default. Revisited once native has run somewhere real. |

Smaller calls, proceeding as stated unless you object:

| # | Question | Proceeding with |
|---|---|---|
| D6a | Key types in v1 | Envelope: RSA, RSA-enc, HMAC, AES — the four a realm gets by default. Native: **EC first** (ES256/384/512), then RSA. EdDSA is impossible natively — see §12. |
| D6b | Does migration delete the legacy component? | No. Deactivate + log the exact deletion command. `?deleteLegacy=true` opt-in. |
| D6c | Bulk migration at startup? | Behind `--spi-kms--migrate-on-startup=true`, default off. Per-realm REST is the supported path. |
| D6d | KMS unreachable at boot? | Fail startup. A security control must not degrade silently. |
| D6e | Cache TTL for unwrapped keys | 5 minutes, configurable, `0` = never cache. |
| D6f | Target Keycloak | 26.7.1, matching the current `serverless` pin. |

---

## 3. Architecture

```
              Keycloak `keys` SPI                              Extension `kms` SPI
 ┌────────────────────────────────────────┐          ┌──────────────────────────────────┐
 │ ENVELOPE (Tier A, default)             │          │ KmsProvider                      │
 │   kms-rsa-generated                    │──wrap───▶│   encrypt(bytes, ctx)            │
 │   kms-rsa-enc-generated                │◀─unwrap──│   decrypt(bytes, ctx)            │
 │   kms-hmac-generated                   │          │   describe(keyId)                │
 │   kms-aes-generated                    │          │                                  │
 │     ↳ unwrap once, cache plaintext,    │          │   sign(keyId, alg, digest)   ◀── Tier B
 │       Keycloak signs in-process        │──sign───▶│   publicKey(keyId)           ◀── Tier B
 ├────────────────────────────────────────┤          └──────────────────────────────────┘
 │ NATIVE (Tier B, premium)               │                 ▲                    ▲
 │   kms-rsa-native                       │        ┌────────┴───────┐   ┌────────┴────────┐
 │     ↳ opaque KmsPrivateKey +           │        │ AwsKmsProvider │   │ LocalKmsProvider│
 │       KmsJcaProvider intercepts        │        │ SigV4 + JDK    │   │ AES-GCM +       │
 │       Signature.initSign               │        │ HttpClient     │   │ in-proc keypair │
 └────────────────────────────────────────┘        └────────────────┘   └─────────────────┘

 ┌────────────────────────────────────────┐
 │ KmsResource (REST, realm-scoped)       │   POST /realms/{r}/kms/migrate
 │                                        │   POST /realms/{r}/kms/rotate
 │                                        │   GET  /realms/{r}/kms/status
 └────────────────────────────────────────┘
```

### Storage format (envelope)

Unchanged from `serverless` — a self-contained value in component config:

```
wrappedMaterial = kms://v1/<base64url(kms-ciphertext-blob)>
```

`v1` is the format version, so a future change is detectable rather than a decrypt failure. Public
material (`certificate`, `publicKey`) stays plaintext, exactly as stock providers store it.

### Storage format (native)

```
kmsKeyId    = arn:aws:kms:us-east-1:111122223333:key/…   (a pointer; no material)
kid         = <RFC 7638 thumbprint of the KMS public key>
publicKey   = <X.509 SubjectPublicKeyInfo, base64>       (cached from kms:GetPublicKey)
certificate = <self-signed X.509, PEM>                   (minted once via kms:Sign — see §5.3)
```

### Encryption context (envelope only)

Every `Encrypt`/`Decrypt` carries `app=keycloak realm=<realmId> kid=<kid> keyType=RSA|HMAC|AES|RSA_ENC`.
KMS treats this as authenticated additional data, so a ciphertext moved between realms, between key
types, or re-labelled with a different kid fails to decrypt. This is the property `serverless`'s
AES-GCM envelope lacks, and it is what makes the extension safe in a shared database with untrusted
realm administrators. It is also enforceable in the key policy, so it is a KMS-side guarantee rather
than a convention in our code.

### Caching

- **Envelope:** static `ConcurrentHashMap<(realmId,kid), Plaintext>` with a TTL, ported from
  `WrappedKeyProviderFactory` — plus what that one is missing: invalidation on component update and
  removal via a `ProviderEventListener` on `ComponentModel` events. Without it, editing a key
  provider leaves a stale key serving for up to the TTL.
- **Native:** no key material to cache. The public key and certificate are cached indefinitely
  (immutable for the CMK's life); signatures are never cached.

---

## 4. Envelope mode (Tier A) — the default

`AbstractKmsKeyProvider` holds the shared logic; four factories differ only in key type and the
config properties they expose, mirroring their stock counterparts field for field so the admin
console looks familiar.

| Provider id | Replaces | Key use |
|---|---|---|
| `kms-rsa-generated` | `rsa-generated` | SIG — RS256/384/512, PS256/384/512 |
| `kms-rsa-enc-generated` | `rsa-enc-generated` | ENC — RSA-OAEP |
| `kms-hmac-generated` | `hmac-generated` | SIG — HS256/384/512 |
| `kms-aes-generated` | `aes-generated` | ENC — AES |

Generation happens in-process: mint the material, `kms:Encrypt` it with the encryption context,
persist only the `kms://v1/` value. Plaintext exists in heap during generation and during use, and
never reaches the database. That is the same exposure as vanilla Keycloak while running and strictly
better at rest — stated plainly in the README rather than glossed.

---

## 5. Native mode (Tier B) — the premium option, **experimental in v1**

Provider ids `kms-ec-native` (ES256/384/512, shipping first) and `kms-rsa-native` (RS/PS, built on
the same machinery). The private key is generated by AWS inside an asymmetric CMK, is not
extractable, and every signature is a `kms:Sign` call. This is the mode where a database compromise
*and* a pod-memory compromise both fail to yield a signing key.

**EC leads (D7).** `ECC_NIST_P256` signs faster and costs less per operation than RSA inside KMS,
ES256 is universally supported by relying parties, and it sidesteps the PSS parameter path entirely.
RSA follows once the EC provider is proven.

**Experimental in v1 (D8).** The interception mechanism below has no production mileage and the mode
carries a hard throughput ceiling. The README, the provider help text, and a startup log line all
say so. Envelope mode is the supported default.

### 5.1 How the signature is intercepted — and the spike that de-risks it

Keycloak's `AsymmetricSignatureSignerContext.sign()` does, verbatim from the 26.7.1 bytecode:

```java
Signature signature = Signature.getInstance(JavaAlgorithm.getJavaAlgorithm(alg, curve));
signature.initSign((PrivateKey) key.getPrivateKey());
signature.update(data);
return signature.sign();
```

No provider is named. The JDK therefore uses **delayed provider selection**: `getInstance` returns a
delegate, and provider choice happens at `initSign(key)` — the first registered provider that
accepts that key wins. `KeyWrapper.setPrivateKey` takes a `java.security.Key`, so we can hand it an
opaque `KmsPrivateKey` (`getFormat()` → `null`, `getEncoded()` → `null`). SunRsaSign rejects it
(`RSAKeyFactory.toRSAKey` needs the modulus), the JDK moves on, and our `KmsJcaProvider` accepts it
and turns `sign()` into `kms:Sign`. No change to Keycloak's signature SPI, no fork, no reflection.
This is the mechanism `aws-kms-jce` uses.

**It is also the single biggest technical risk in the plan**, because it depends on JDK behaviour we
have reasoned about but not observed here. So it is **task 1 of the native work**: a ~30-line spike
that registers a stub provider, hands Keycloak an opaque key, and asserts our `engineSign` is
reached. Half a day, before anything is built on top of it.

**Plan B if delayed selection does not hold:** implement `SignatureProviderFactory` for RS256/384/512
and PS256/384/512, branching on whether the `KeyWrapper`'s private key is ours and delegating to the
stock implementation otherwise. It works, but it is a *global* override of Keycloak's signature
providers — every realm's signing path runs through our code, including realms not using this
extension. That is a much larger blast radius, and if the spike fails I would want to revisit
whether native mode is worth it before taking that on.

PSS adds a wrinkle: `PS256` maps to `RSASSA-PSS`, whose parameters arrive via
`Signature.setParameter(PSSParameterSpec)`. The JCA `SignatureSpi` must implement
`engineSetParameter` and translate to the matching KMS `SigningAlgorithm`
(`RSASSA_PSS_SHA_256`). Covered by the spike.

### 5.2 CMK lifecycle — bring your own key

The extension **does not create and does not delete** asymmetric CMKs. The admin creates the key,
pastes the ARN into the provider's `kmsKeyId`, and the extension calls `kms:GetPublicKey` and
`kms:DescribeKey` to validate spec and usage at creation time.

The reasoning is cost and blast radius. An asymmetric CMK is $1/month and lives until someone
schedules its deletion; if the extension created keys implicitly, a realm deleted in the console
would silently orphan a billable key forever, and a bug in cleanup logic would schedule the deletion
of a key that still signs production tokens. Neither failure is acceptable for something we would
have to get right at scale. Auto-creation is available behind
`--spi-kms--aws--allow-key-creation=true` for people who want it, and even then deletion stays
manual, with the orphan risk documented.

At provider creation the extension logs the cost and quota implications explicitly, because "$1 per
realm per month" and "the asymmetric quota caps how fast this cluster can issue tokens" are exactly
the facts that get discovered too late.

### 5.3 The certificate problem

Keycloak's RSA providers carry a self-signed X.509 certificate, and SAML descriptor endpoints and
some client-authentication flows read it. With a non-extractable key we cannot mint one the usual
way — but we do not need the private key in hand, only a signature over the TBS structure. So the
certificate is minted **once at provider creation** by building the TBS bytes and signing them with
`kms:Sign`, then stored as PEM in component config. It is public material; storing it in the
database is correct.

If that proves fiddlier than expected, the fallback is to omit the certificate and document that
native mode does not support SAML signing in v1. I would rather mint it — an RSA realm key without a
certificate is a surprising gap.

### 5.4 Migration into native mode: deliberately not supported

AWS KMS can import asymmetric key material, but it is a multi-step ceremony
(`GetParametersForImport` → wrap with `RSA_AES_KEY_WRAP_SHA_256` → `ImportKeyMaterial`), and imported
material cannot be automatically rotated and may expire.

It is also the wrong thing to want. Native mode's value is that the private key has *never* existed
outside the HSM; importing a key that spent years in a Postgres table throws that away while keeping
all the costs. So:

> **Native mode is generate-only.** An admin who wants it migrates to envelope mode first
> (zero-downtime, same kid), then rotates to a native provider — a new kid via standard Keycloak
> passive-key semantics, and material that has never touched the database.

This is a better security story than import, and it removes the import ceremony from the plan
entirely.

### 5.5 Throughput

`kms:Sign` on an asymmetric CMK draws on a per-region, per-account quota measured in the low
hundreds to ~1,000 requests/second depending on key spec and region, shared across every asymmetric
operation in the account. One token issuance is one call. The extension retries `ThrottlingException`
with exponential backoff and surfaces a distinct error rather than a generic 500, and the docs give
the Service Quotas console link and a worked example of when a realm outgrows this mode.

---

## 6. Migration (into envelope mode)

The part with the sharp edges.

**Reading legacy material.** Stock storage, confirmed against Keycloak 26.7.1 bytecode:

| Provider | Config keys | Encoding |
|---|---|---|
| `rsa-generated`, `rsa`, `rsa-enc-generated`, `rsa-enc` | `privateKey`, `certificate` | PEM, via `PemUtils.decodePrivateKey` |
| `hmac-generated`, `aes-generated` | `secret`, `secretSize` | `Base64Url` |

**Preserving the kid.** This is what makes migration zero-downtime, and it is easy to get wrong.
`AbstractRsaKeyProvider` uses `model.get("kid")` when present and otherwise derives
`KeyUtils.createKeyId(publicKey)` — the RFC 7638 JWK thumbprint. The migrator resolves the kid the
same way and writes it **explicitly** into the new component's `kid` config, so it is pinned rather
than re-derived. Secret providers already store an explicit `kid`; it is copied verbatim.

Consequence: every key JWKS publishes is unchanged across the migration, every issued token keeps
verifying, there is no window. That property is the acceptance test. (The `keys` array may be
re-ordered — a JWK Set is unordered by RFC 7517 and clients select by kid — so the test compares
the set keyed by kid rather than the document.)

**Transaction shape.** Per key, inside one Keycloak transaction:

1. Read and decode the legacy material.
2. `kms:Encrypt` with the encryption context. *(The only step that can fail on an external system —
   deliberately before any write.)*
3. `addComponentModel` for the KMS provider: same priority, same algorithm, same `active`/`enabled`,
   pinned `kid`, `wrappedMaterial`, public material copied across.
4. **Round-trip verification before committing:** decrypt what was just written, rebuild the key,
   assert the public key matches the legacy one. A migration that writes an unreadable ciphertext
   must fail loudly here, not at the next login.
5. Deactivate the legacy component (`active=false`, `enabled=false`) so no duplicate kid reaches
   JWKS.
6. Log the deletion instruction with the component id.

Idempotent: a realm already carrying a KMS provider for a given kid is reported under `skipped`.
Re-runnable after a partial failure.

**Stated in the log, the API response and the README, not buried:** migrated material was at rest in
plaintext and is in existing backups, snapshots and replicas. Migration closes the ongoing exposure;
only rotation to never-persisted material closes the historical one. `POST /kms/rotate` does that.

---

## 7. Repository layout

Modelled on `keycloak-transactional-email`.

```
pom.xml                      io.phasetwo.keycloak:keycloak-kms, parent io.phasetwo:oss-parent
README.md  COPYING (ELv2)  AGENTS.md  Makefile  docker-compose.yml
.github/workflows/{ci,release,coverage}.yml     (synced from p2-inc/shared-github-actions)
docs/{user-story,implementation-plan,aws-setup,configuration,migration,native-mode}.md
docker/{dev-realm.json,localstack-init.sh}

src/main/java/io/phasetwo/keycloak/kms/
  spi/         KmsSpi, KmsProvider, KmsProviderFactory, EncryptionContext, KmsKeySpec
  aws/         AwsKmsProvider(Factory), AwsSigV4Signer, KmsApi, KmsErrors,
               credentials/{CredentialsProvider,Chain,Environment,WebIdentity,
                            ContainerCredentials,InstanceProfile,Static}
  local/       LocalKmsProvider(Factory)              — static KEK + in-proc keypair, dev/test only
  keys/        AbstractKmsKeyProvider(Factory), KeyCache, WrappedMaterial (kms://v1/ codec),
               envelope/{KmsRsaKeyProvider,KmsRsaEncKeyProvider,
                         KmsHmacKeyProvider,KmsAesKeyProvider}(Factory)
               native/  {KmsRsaNativeKeyProvider(Factory), KmsPrivateKey, KmsJcaProvider,
                         KmsSignatureSpi, SelfSignedCertMinter}
  migration/   KmsKeyMigrator, LegacyKeyReader, MigrationReport
  resource/    KmsResourceProvider(Factory), KmsResource, AbstractAdminResource
  bootstrap/   NewRealmKeyInstaller, StartupMigrator
```

`@AutoService` for SPI discovery, `@JBossLog` for logging, `representation` package naming, all
Keycloak deps `provided`, `mvn fmt:format` (Google Java style) — house conventions throughout.

---

## 8. Configuration surface

Server level (Keycloak 26 double-separator form; the legacy single-dash form still resolves with a
deprecation warning):

| Option | Default | Meaning |
|---|---|---|
| `--spi-kms--provider` | — | `aws` or `local` |
| `--spi-kms--aws--region` | AWS region chain | Region for the KMS endpoint |
| `--spi-kms--aws--key-id` | — | Default symmetric CMK for envelope mode |
| `--spi-kms--aws--endpoint` | derived | Override, for LocalStack |
| `--spi-kms--aws--allow-key-creation` | `false` | Permit the extension to create asymmetric CMKs |
| `--spi-kms--cache-ttl-seconds` | `300` | Plaintext cache TTL (envelope); `0` disables |
| `--spi-kms--default-for-new-realms` | `false` | Install envelope providers on realm creation |
| `--spi-kms--migrate-on-startup` | `false` | Sweep all realms at boot |

Per component (Realm settings → Keys → Providers): the stock fields, plus `kmsKeyId` — optional in
envelope mode (per-realm CMK), **required** in native mode (the asymmetric CMK to sign with).

---

## 9. Testing

House harness: `testcontainers-keycloak` + REST-Assured, JaCoCo in CI. KMS comes from a
**LocalStack** container, so the AWS path runs against real KMS API semantics with no account.

> **Verify early:** LocalStack Community's asymmetric `Sign` / `GetPublicKey` support gates the
> native-mode integration tests. Checked during the §5.1 spike. If it is absent or wrong, the
> fallback is a small in-process KMS stub served over `HttpServer` — the SigV4 tests already need
> one, so the incremental cost is low.

Unit, no Docker:

- SigV4 against AWS's published signing test-suite vectors — canonical request, string-to-sign and
  Authorization header compared literally.
- Credential chain: each source in isolation against a stubbed metadata endpoint, plus precedence.
- `kms://v1/` codec round-trip and rejection of malformed values.
- Cache TTL, expiry, invalidation on component change.
- Certificate minter: TBS bytes signed by a local key produce a cert that verifies (the same code
  path native mode drives through `kms:Sign`).

Integration, LocalStack + Keycloak:

| # | Test | Proves |
|---|---|---|
| 1 | Add `kms-rsa-generated` → obtain token → verify against JWKS | The baseline |
| 2 | Restart the container → same kid, same public key | Material lives outside pod memory |
| 3 | Two containers, one CMK → token from A verifies on B | Multi-instance property (ported from `instance/multi-smoke.sh`) |
| 4 | Migrate a realm with stock `rsa-generated` | Every published key unchanged (compared as a kid-keyed set), kid unchanged, pre-migration token still verifies, legacy deactivated, log emitted with correct component id |
| 5 | Copy realm A's `wrappedMaterial` into realm B | Decrypt denied — the tenancy property |
| 6 | Revoke KMS access | Cold start fails; running pod 503s rather than regenerating a DB-backed key |
| 7 | Rotate | New kid at higher priority, old kid still passive in JWKS, old tokens still verify |
| 8 | `SELECT` over `COMPONENT_CONFIG` after legacy deletion | No `privateKey` / `secret` row remains — the audit finding, as an assertion |
| 9 | **Native:** add `kms-rsa-native` → obtain token → verify against JWKS | Tier B end to end |
| 10 | **Native:** no plaintext private key anywhere | Component config holds only an ARN; `kms:Sign` call count == tokens issued |
| 11 | **Native:** ES256 and RS256 both verify | Both curve and PSS parameter paths (§5.1) |
| 12 | **Native:** envelope realm and native realm in one server | The JCA provider does not disturb realms that do not use it |

Test 12 is the one that would catch the worst native-mode failure mode — a JCA registration that
changes signing behaviour for realms that never opted in.

---

## 10. Build order

| # | Task | Depends on |
|---|---|---|
| 1 | Repo furniture: pom, `oss-parent`, ELv2 `COPYING`, CI workflows, `.editorconfig`, fmt plugin | — |
| 2 | **Spike: JCA delayed provider selection (§5.1)** — half a day, gates all native work | 1 |
| 3 | `kms` SPI + `LocalKmsProvider` + `kms://v1/` codec (port from `serverless`) | 1 |
| 4 | `AwsSigV4Signer` (adapt from `keycloak-transactional-email`) + `KmsApi` + SigV4 vector tests | 1 |
| 5 | Credential chain + tests | 4 |
| 6 | `AwsKmsProvider` (encrypt/decrypt/describe), encryption context, boot-time fail-fast | 3–5 |
| 7 | `AbstractKmsKeyProvider` + `kms-rsa-generated` + key cache + invalidation | 3, 6 |
| 8 | LocalStack harness + integration tests 1–3 | 7 |
| 9 | HMAC, AES, RSA-enc envelope factories | 7 |
| 10 | `KmsKeyMigrator` + REST resource + tests 4, 8 | 9 |
| 11 | Rotation, `NewRealmKeyInstaller`, `StartupMigrator` | 10 |
| 12 | Fail-closed + encryption-context isolation tests (5, 6) | 10 |
| 13 | Native: `kms:Sign` / `GetPublicKey` in `AwsKmsProvider`; `KmsPrivateKey`, `KmsJcaProvider`, `KmsSignatureSpi` (ECDSA first) | 2, 6 |
| 14 | Native: `kms-ec-native` then `kms-rsa-native`, BYO-CMK validation, `SelfSignedCertMinter` | 13 |
| 15 | Native: integration tests 9–12 | 14 |
| 16 | `docker-compose` + `Makefile` dev env (Keycloak + LocalStack + seeded realm, both modes) | 9, 14 |
| 17 | README, `aws-setup.md`, `configuration.md`, `migration.md`, `native-mode.md`, `AGENTS.md` | 11, 15 |

Task 2 is deliberately early and out of dependency order: it is cheap, and if it fails the native
scope needs re-discussing before tasks 13–15 are committed to. There is a demoable end-to-end at 8
(a realm signing with a KMS-held key), envelope mode is complete at 12, and native mode at 15.

---

## 11. Risks

| Risk | Handling |
|---|---|
| **JCA delayed provider selection does not behave as reasoned** — native mode's whole interception approach | §5.1 spike as task 2, before anything depends on it. Plan B (global `SignatureProviderFactory` override) works but has a much larger blast radius; if the spike fails, native scope gets re-discussed rather than force-fit. |
| **Native mode's JCA provider affects realms that did not opt in** | Test 12 specifically. The provider is appended last and only accepts `KmsPrivateKey`. |
| **Hand-rolled SigV4 subtly wrong** — fails only for some payloads or regions | AWS published test vectors as unit tests; LocalStack validates real signatures. Escape hatch: swap in the SDK. |
| **Credential chain gaps** in an environment we do not run | Each source independently tested; documented precedence; explicit static config as the always-works fallback. |
| **CMK loss is unrecoverable** and takes every realm with it | Documented as *the* catastrophic failure mode: multi-Region key, 30-day deletion window, CloudWatch alarm on `DisableKey` / `ScheduleKeyDeletion`. |
| **Orphaned asymmetric CMKs** billing $1/mo forever after a realm is deleted | BYO-CMK by default (§5.2); the extension never creates or deletes keys unless explicitly permitted, and never deletes even then. |
| **Migration corrupts a realm's keys** — locks every user out | Round-trip verification before commit; legacy component deactivated, never deleted; reactivating it is a complete rollback. |
| **`kc.sh build` conflicts** from extension dependencies | Zero runtime dependencies beyond what Keycloak ships — what D2 buys. |
| **Keycloak internals shift** — `Attributes` keys, kid derivation, signer context | Pinned to 26.7.1; integration tests read real stock-generated components rather than fixtures, so a change in stock behaviour fails a test instead of silently diverging. |

---

## 12. Still open

1. **LocalStack asymmetric KMS support** — resolved during task 2; determines whether native-mode
   integration tests run against LocalStack or an in-process stub. Low impact either way.
2. **EdDSA (Ed25519).** AWS KMS has no EdDSA key spec, so native mode cannot support it at all —
   only envelope mode could. Worth stating in the docs as a hard limit rather than a gap.
