# Migrating existing realms

Moving a realm that already has keys in the database, without anything downstream noticing.

## What migration does

For each migratable key provider in the realm:

1. Read the existing plaintext material — PEM PKCS#8 for keypairs, base64url for secrets.
2. Resolve the kid **exactly as the stock provider does**: the `kid` in config if present,
   otherwise the RFC 7638 thumbprint of the public key.
3. Encrypt the material under the KMS key, bound to `{app, realm, kid, keyType}`.
4. Read it straight back and compare, before writing anything.
5. Create a KMS-backed provider with the same kid, same priority, same algorithm, same certificate.
6. Deactivate the legacy provider so no duplicate kid reaches JWKS.
7. Log exactly what still holds plaintext and how to remove it.

Because step 2 reproduces the kid, **every key JWKS publishes is unchanged**. Tokens already issued
keep verifying, clients re-fetch nothing, and there is no window.

*(The order of the `keys` array can change — the migrated providers are new rows. A JWK Set is
unordered by RFC 7517 and clients select by `kid`, so this is invisible to anything reading it
correctly. Worth knowing before you diff two JWKS documents.)*

## Running it

```bash
TOKEN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password -d username=admin -d password=admin \
  | jq -r .access_token)

curl -X POST "$KC/realms/customer-a/kms/migrate" -H "Authorization: Bearer $TOKEN" | jq
```

```json
{
  "realm": "customer-a",
  "migrated": [
    { "keyType": "RSA", "kid": "wA88OF…", "from": "rsa-generated",
      "to": "kms-rsa-generated", "legacyComponentId": "499c696f…",
      "newComponentId": "3479a3a3…", "legacyDeleted": false }
  ],
  "skipped": [],
  "plaintextRemains": true,
  "warnings": [
    "Migrated key material was previously stored in plaintext…",
    "The legacy providers are deactivated but still present…"
  ]
}
```

Idempotent: run it again and everything is reported under `skipped` as already KMS-backed. A run
that failed part-way can simply be repeated.

## `plaintextRemains`

The one field to check. `true` means something in this realm still holds usable key material —
either the deactivated legacy providers, or a key type this version cannot migrate.

```bash
curl -s "$KC/realms/customer-a/kms/status" -H "Authorization: Bearer $TOKEN" | jq '.plaintextRemains'
```

## Deleting the legacy providers

Not done by default. While the legacy component exists, re-enabling it is a complete rollback;
once deleted it is gone. The log names each one:

```
WARN  kms: realm 'customer-a': key material for kid wA88OF… is now held in the KMS. The legacy
      provider 'rsa-generated' (component 499c696f…) is deactivated but its row in COMPONENT_CONFIG
      STILL CONTAINS THE PLAINTEXT privateKey. It is now safe to delete the legacy provider.
      Until you do, the plaintext key is still in your database.
        Admin console -> Realm settings -> Keys -> Providers -> delete 'rsa-generated'
        or: DELETE /admin/realms/customer-a/components/499c696f…
```

Once you trust it — typically after confirming logins still work on the first realm — do it in one
step for the rest:

```bash
curl -X POST "$KC/realms/customer-b/kms/migrate?deleteLegacy=true" -H "Authorization: Bearer $TOKEN"
```

## Migration is step one of two

The material that was just encrypted **was in the database in plaintext**. It is in last night's
snapshot, in the WAL, in whatever the backup pipeline shipped, and in any read replica. Encrypting
it now stops further exposure. It does not undo past exposure, and no amount of encryption will.

Once tokens signed by the old kid have expired, rotate onto material that has never touched the
database:

```bash
curl -X POST "$KC/realms/customer-a/kms/rotate?keyType=RSA" -H "Authorization: Bearer $TOKEN" | jq
```

```json
{
  "realm": "customer-a",
  "keyType": "RSA",
  "newKid": "Rk9…",
  "newPriority": 200,
  "previousKids": ["wA88OF…"],
  "nextSteps": [
    "New tokens are signed with kid Rk9… from now on.",
    "Leave the previous providers in place until every token they signed has expired — at minimum
     the realm's access-token lifespan, and longer if refresh tokens or offline sessions are in play.",
    "Then set them inactive (active=false) to stop publishing them, and delete them once nothing
     complains."
  ]
}
```

Standard Keycloak rotation semantics: the new key signs, the old one stays published for
verification until you retire it.

## What is not migrated

Reported in `skipped` with a reason, never silently ignored.

| Provider | Why |
|---|---|
| `ecdsa-generated` | No EC envelope provider in this version. The private key stays in the database. |
| `eddsa-generated` | AWS KMS has no Ed25519 key spec, and there is no EdDSA envelope provider yet. |
| `java-keystore` | Already keeps its material outside the database, in a keystore file. Migrating is possible but not automated. |
| `kms-*` | Already KMS-backed. |

A realm with any of these still has a private key in the database, and `plaintextRemains` stays
`true` to say so.

## Failures

Migration is per key. If one fails — a KMS outage, a permission gap — that key is left exactly as
it was, still enabled and still working, and reported under `skipped` with the error. The others
still migrate. Nothing is left half-written: the seal and its read-back verification both happen
before any database write.

## Migrating a whole fleet

`--spi-kms--migrate-on-startup=true` sweeps every realm at boot, deactivating but never deleting.
It is off by default because a sweep across every realm is a lot of KMS calls and a lot of writes to
perform without being asked, and because doing the first realm by hand and reading the output is a
better way to find out that something is misconfigured.

## Trying it

`make dev` starts Keycloak and LocalStack with a `dev` realm that has ordinary Keycloak keys.
`./docker/migrate-dev.sh` runs the migration and prints the kid list before and after.
