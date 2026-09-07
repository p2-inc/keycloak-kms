# keycloak-kms

Keeps Keycloak's realm signing keys in a cloud KMS instead of in the database.

Out of the box, Keycloak stores realm keys as rows in `COMPONENT_CONFIG`: `rsa-generated` keeps a
PEM-encoded PKCS#8 private key in `privateKey`, `hmac-generated` and `aes-generated` keep base64url
secrets in `secret`. There is no encryption at the application layer, so anyone with read access to
the database — a DBA, a backup pipeline, a read replica, a stolen snapshot — can extract the signing
key and mint valid tokens for any user. Database-level encryption at rest does not address that,
because all of those see plaintext.

This extension replaces those providers with ones whose private material the database never holds.

```
                    stock Keycloak                        with keycloak-kms
COMPONENT_CONFIG    privateKey = -----BEGIN PRIVATE KEY   wrappedMaterial = kms://v1/AQICAHg…
                                 MIIEvQIBADANBgkqhki…                        (KMS ciphertext)
```

---

## Two modes

|  | **Envelope** *(default)* | **Native** *(experimental)* |
|---|---|---|
| Provider ids | `kms-rsa-generated`, `kms-rsa-enc-generated`, `kms-hmac-generated`, `kms-aes-generated` | `kms-ec-native`, `kms-rsa-native` |
| Where the private key lives | Encrypted under a KMS key; the ciphertext is in the database | Inside KMS, non-extractable |
| Signing | In this process, at memory speed | One `kms:Sign` per token |
| Added latency | None | Single-digit to low-tens of milliseconds per token |
| Cost | One CMK, about $1/month for the whole cluster | One CMK **per realm key**, plus per-signature charges |
| Throughput | Unlimited | Capped by the KMS asymmetric-operation quota, which is account-wide |
| Survives a database compromise | Yes | Yes |
| Survives a **process memory** compromise | No | Yes |

**Start with envelope mode.** It closes the finding almost everyone actually has, costs a dollar,
and adds no latency. Native mode exists for the realm whose contract says the key must never leave
an HSM; it is [documented separately](docs/native-mode.md) and is marked experimental in this
release.

## Install

```dockerfile
FROM quay.io/keycloak/keycloak:26.7.3
COPY keycloak-kms.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
```

Then point it at a KMS key:

```bash
kc.sh start \
  --spi-kms--provider=aws \
  --spi-kms--aws--region=us-east-1 \
  --spi-kms--aws--key-id=alias/keycloak-realm-keys
```

On boot the extension calls `kms:DescribeKey` once and logs what it found:

```
INFO  [io.phasetwo.keycloak.kms.aws.AwsKmsProviderFactory] keycloak-kms: AWS KMS ready —
      key=arn:aws:kms:us-east-1:111122223333:key/3f2b… (SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT, enabled)
      region=us-east-1 credentials=web-identity
```

If the key is missing, disabled, of the wrong type, or the role cannot reach it, **Keycloak refuses
to start**. A key-custody control that starts anyway and quietly leaves realms on database-backed
keys is worse than not installing one, because the operator sees a healthy server.

See [docs/aws-setup.md](docs/aws-setup.md) for the key, the IAM policy and the credential options,
and [docs/configuration.md](docs/configuration.md) for every setting.

## Migrate the realms you already have

Per realm, idempotent, and invisible to relying parties:

```bash
curl -X POST "https://sso.example.com/realms/customer-a/kms/migrate" \
  -H "Authorization: Bearer $TOKEN"
```

The kid does not change, and neither does the public key — the extension reads the existing private
key, encrypts it, and writes a KMS-backed provider carrying the same material at the same priority.
Every token already issued keeps verifying. There is no rotation, no re-login, no window.

The legacy provider is deactivated but **not deleted**, and the log says exactly what to remove:

```
WARN  kms: realm 'customer-a': key material for kid gT7pQ… is now held in the KMS. The legacy
      provider 'rsa-generated' (component 8a1f-…) is deactivated but its row in COMPONENT_CONFIG
      STILL CONTAINS THE PLAINTEXT privateKey. It is now safe to delete the legacy provider.
      Until you do, the plaintext key is still in your database.
        Admin console -> Realm settings -> Keys -> Providers -> delete 'rsa-generated'
        or: DELETE /admin/realms/customer-a/components/8a1f-…
```

Deleting a key provider is irreversible, and while the legacy component exists re-enabling it is a
complete rollback. Pass `?deleteLegacy=true` once you are confident.

> **Migration alone does not close the finding.** The material it moved was in plaintext in the
> database, so it is also in last night's snapshot, in the WAL, and in any read replica. Encrypting
> it stops further exposure; it does not undo past exposure. Once tokens signed by the old kid have
> expired, rotate to material that has never touched the database:
>
> ```bash
> curl -X POST ".../realms/customer-a/kms/rotate?keyType=RSA" -H "Authorization: Bearer $TOKEN"
> ```

Full walkthrough: [docs/migration.md](docs/migration.md).

## REST API

Base path `/realms/{realm}/kms`. `GET` needs `view-realm`, `POST` needs `manage-realm`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/status` | Every key provider in the realm: whether it is KMS-backed, whether it still holds plaintext, its kid and priority. `plaintextRemains` answers the audit question directly. |
| `POST` | `/migrate` | Move every migratable key into the KMS. `?deleteLegacy=true` also removes the legacy providers. |
| `POST` | `/rotate` | Generate a fresh KMS-held key and promote it. `?keyType=RSA\|RSA_ENC\|HMAC\|AES`. |

## What it will not do

- **EC and EdDSA envelope keys.** `ecdsa-generated` and `eddsa-generated` are reported by
  `/migrate` as left behind, with a reason, rather than silently ignored — a realm with an
  unmigrated key has not closed the finding and must not report that it has. (AWS KMS has no
  Ed25519 key spec at all, so EdDSA can never be native.)
- **Create or delete asymmetric CMKs.** Native mode is bring-your-own-key. An asymmetric CMK bills
  for as long as it exists, so implicit creation would orphan a billable key every time a realm was
  deleted, and implicit deletion would eventually destroy a key that was still signing.
- **Ship a UI.** Configuration is server-level and per-realm actions are REST, consistent with
  every other Phase Two extension.

## Development

```bash
make dev        # build the jar, start Keycloak + LocalStack, no AWS account needed
make test       # unit tests, no Docker
make verify     # everything, including the LocalStack and Keycloak integration suites
```

`make dev` imports a `dev` realm with ordinary Keycloak keys, so there is something to migrate.
`./docker/migrate-dev.sh` runs the migration and diffs the JWKS before and after.

See [docs/development.md](docs/development.md).

## Compatibility

Keycloak 26.7.x, Java 21. The extension ships no runtime dependencies of its own: AWS is reached
with hand-rolled SigV4 over the JDK HTTP client, so there is nothing to conflict with Keycloak's
Quarkus runtime and nothing to keep up to date for CVEs.

Keycloak logs `KC-SERVICES0047: … is implementing the internal SPI keys` for each provider at build
time. That is expected — the `keys` SPI is marked internal by Keycloak, and every key-provider
extension gets the same warning.

## License

[Elastic License 2.0](COPYING).
