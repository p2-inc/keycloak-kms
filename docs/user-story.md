# User story — installing and operating `keycloak-kms`

> Status: **proposal, for review.** Nothing here is built yet. This document describes the
> experience we intend to deliver; `implementation-plan.md` describes how, and lists the decisions
> that are still open.

## The person

Dana runs a self-hosted Keycloak cluster (three pods on EKS, Postgres RDS behind it) for a company
that has just failed a control in a SOC 2 audit:

> *Private signing keys for the identity provider are stored unencrypted in the application
> database. Any principal with read access to the database, a snapshot, or a logical backup can
> extract the RSA private key and mint valid access tokens for any user.*

The finding is accurate. Keycloak stores realm keys as `COMPONENT` / `COMPONENT_CONFIG` rows:
`rsa-generated` keeps a PEM-encoded PKCS#8 private key in the `privateKey` config value,
`hmac-generated` and `aes-generated` keep base64url secrets in `secret`. There is no encryption at
the application layer. RDS encryption-at-rest does not address the finding, because the DBA, the
backup pipeline, and anything with a read replica all see plaintext.

Dana wants the private keys out of the database and under AWS KMS, without changing how Keycloak
issues tokens and without an outage.

---

## 1. Prepare AWS

Dana creates one symmetric KMS key. It protects realm key material for the whole cluster.

```bash
aws kms create-key \
  --description "Keycloak realm signing keys" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --tags TagKey=app,TagValue=keycloak

aws kms create-alias \
  --alias-name alias/keycloak-realm-keys \
  --target-key-id <key-id>
```

**Multi-region.** If Keycloak runs in more than one region, this must be a multi-Region key
(`--multi-region`) with a replica in each, or every `Decrypt` from the remote region crosses the
internet and adds latency to a cold key load. Deciding this after the fact means re-encrypting every
realm, so the setup doc will lead with it.

**Automatic rotation is safe to leave on.** KMS retains previous backing keys, so ciphertext written
before a rotation still decrypts. Nothing in Keycloak needs to know.

### IAM

The Keycloak pods need very little:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
    "Resource": "arn:aws:kms:us-east-1:111122223333:key/<key-id>",
    "Condition": {
      "StringEquals": { "kms:EncryptionContext:app": "keycloak" }
    }
  }]
}
```

`kms:Encrypt` is only exercised when a key is generated, migrated, or rotated. A hardened
deployment can split the policy so that steady-state pods hold `Decrypt` only and an operator role
holds `Encrypt` — the docs will show both.

The `EncryptionContext` condition is not decoration. The extension binds every ciphertext to
`{app, realm, kid, keyType}`, so a ciphertext lifted out of realm A's config and pasted into realm
B's will fail to decrypt — the condition makes that a KMS-enforced property rather than a
convention.

*(Realms using the sign-in-KMS mode of §8 need `kms:Sign` and `kms:GetPublicKey` on their own
asymmetric CMK. Those keys carry no encryption context — there is nothing to encrypt — so they get
a separate statement scoped to their ARNs.)*

### Credentials

No access keys. The extension resolves credentials the way every AWS tool does, in order:

| Source | Detected by |
|---|---|
| Static credentials in extension config | explicit config (documented, discouraged) |
| Environment | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` |
| EKS Pod Identity | `AWS_CONTAINER_CREDENTIALS_FULL_URI` |
| ECS task role | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` |
| IRSA (web identity) | `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` |
| EC2 instance profile | IMDSv2 |

Dana is on EKS, so this is an IRSA annotation on the service account and nothing else:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/keycloak-kms
```

---

## 2. Install the extension

One JAR into `providers/`, then the usual build step.

```dockerfile
FROM quay.io/keycloak/keycloak:26.7.1
COPY keycloak-kms.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build
```

## 3. Configure

Two settings — which KMS backend, and which key.

```bash
kc.sh start \
  --spi-kms--provider=aws \
  --spi-kms--aws--region=us-east-1 \
  --spi-kms--aws--key-id=alias/keycloak-realm-keys
```

Or as environment variables, which is what Dana actually uses:

```yaml
KC_SPI_KMS__PROVIDER: aws
KC_SPI_KMS__AWS__REGION: us-east-1
KC_SPI_KMS__AWS__KEY_ID: alias/keycloak-realm-keys
```

On boot the extension calls `kms:DescribeKey` once and logs what it found. If the key is missing,
disabled, or the role lacks permission, **Keycloak fails to start** rather than silently falling
back to database-stored keys — a security control that degrades quietly is worse than one that
isn't there.

```
INFO  [io.phasetwo.keycloak.kms] KMS provider 'aws' ready
      key=arn:aws:kms:us-east-1:111122223333:key/3f2b… (SYMMETRIC_DEFAULT, ENCRYPT_DECRYPT, enabled)
      region=us-east-1 credentials=web-identity(arn:aws:iam::111122223333:role/keycloak-kms)
```

## 4. New realms get KMS keys automatically

With `--spi-kms--default-for-new-realms=true`, a realm created through the admin console or the
admin REST API gets `kms-rsa-generated`, `kms-hmac-generated`, and `kms-aes-generated` providers
instead of the stock ones. Nothing in the console looks different except the provider name in
**Realm settings → Keys → Providers**.

Without the flag, Dana adds a provider by hand: **Add provider → `kms-rsa-generated`**. It offers
the same fields as `rsa-generated` (priority, algorithm, key size) plus an optional per-provider
`kmsKeyId` for realms that need their own CMK.

## 5. Migrate the realms that already exist

Dana has 40 realms with keys already in the database. Migration is per realm and idempotent:

```bash
curl -X POST "https://sso.example.com/realms/customer-a/kms/migrate" \
  -H "Authorization: Bearer $TOKEN"
```

```json
{
  "realm": "customer-a",
  "migrated": [
    { "keyType": "RSA",  "kid": "gT7pQ…", "from": "rsa-generated",  "to": "kms-rsa-generated",  "legacyComponentId": "8a1f…" },
    { "keyType": "HMAC", "kid": "b2c9…", "from": "hmac-generated", "to": "kms-hmac-generated", "legacyComponentId": "c4e2…" },
    { "keyType": "AES",  "kid": "e5d1…", "from": "aes-generated",  "to": "kms-aes-generated",  "legacyComponentId": "7b90…" }
  ],
  "skipped": []
}
```

**The kid does not change, and neither does the public key.** The extension reads the existing
private key, encrypts it under the CMK, and writes a KMS-backed provider carrying the *same* key
material at the *same* priority — so JWKS is byte-identical before and after, and every token
already in the wild keeps verifying. There is no rotation, no re-login, no window.

The legacy component is left in place but deactivated (`active=false`, `enabled=false`) so it
contributes nothing to JWKS and no duplicate kid appears. Then the message Dana is waiting for:

```
WARN  [io.phasetwo.keycloak.kms] realm 'customer-a': key material for kid gT7pQ… is now held in
      AWS KMS. The legacy provider 'rsa-generated' (component 8a1f-…) is deactivated but its row
      in COMPONENT_CONFIG STILL CONTAINS THE PLAINTEXT PRIVATE KEY. It is now safe to delete:
        Admin console → Realm settings → Keys → Providers → delete 'rsa-generated'
        or: DELETE /admin/realms/customer-a/components/8a1f-…
      Until you do, the audit finding stands.
```

The extension does not delete it. Deleting a key provider is destructive and irreversible, and if
anything about the migration is wrong the legacy component is the only way back. Dana deletes it
after confirming logins still work — or passes `?deleteLegacy=true` once confident enough to do it
in one step across the remaining 39 realms.

### The honest caveat, stated in the docs and in the response

Migrated material *was* in the database in plaintext. It is in last night's snapshot, in the WAL, in
whatever the backup pipeline shipped to S3, and possibly in a read replica. Encrypting it now does
not un-disclose it.

So migration is step one of two. Once tokens signed by the old kid have expired, Dana rotates to
material that has never touched the database:

```bash
curl -X POST ".../realms/customer-a/kms/rotate?keyType=RSA" -H "Authorization: Bearer $TOKEN"
```

This generates a fresh keypair, wraps it under the CMK, and adds it at a higher priority; the
migrated key stays published in JWKS as passive until Dana removes it. Standard Keycloak rotation
semantics — the extension just makes sure the new material is generated in memory and only ever
persisted encrypted.

## 6. Verify

Three checks the docs will spell out, because "it seems to work" is not evidence:

1. **The database no longer holds a usable key.**
   ```sql
   SELECT c.provider_id, cc.name, left(cc.value, 40)
     FROM component c JOIN component_config cc ON cc.component_id = c.id
    WHERE c.provider_type = 'org.keycloak.keys.KeyProvider';
   ```
   The `kms-*` rows show `wrappedMaterial` values beginning `kms://v1/` — ciphertext. No
   `privateKey`, no `secret`.

2. **Tokens still verify.** Fetch `/realms/customer-a/protocol/openid-connect/certs`, obtain a
   token, verify the signature against the published JWK. Same kid as before migration.

3. **Removing KMS access breaks it.** Detach the IAM policy, restart a pod, and confirm the realm
   fails to serve tokens rather than quietly regenerating a database-backed key. This is the test
   that proves the control is load-bearing.

## 7. Day two

For the envelope mode described above; the sign-in-KMS mode of §8 has a different cost and
latency profile, stated there.

| Situation | What happens |
|---|---|
| KMS unreachable / throttled | Keys already unwrapped keep serving from the in-memory cache (default 5 min TTL). A cold pod cannot serve the realm and returns 503 for token endpoints. It does not fall back to the database. |
| CMK disabled or scheduled for deletion | Every realm loses its signing keys once caches expire. The docs will call this the single catastrophic failure mode and recommend a CloudWatch alarm on `ScheduleKeyDeletion` / `DisableKey` and the maximum 30-day deletion window. |
| Cost | One CMK is $1/month. `Decrypt` is $0.03 per 10,000 requests and happens once per realm per pod per cache TTL — for 40 realms and 3 pods, roughly 35,000 calls/month, about $0.10. Effectively free. |
| Latency | Nothing on the token hot path. Signing stays in-process; KMS is touched only on a cache miss (single-digit ms, region-local). |
| Disaster recovery | The CMK is the root of trust for every realm. Losing it is unrecoverable — the docs will state that plainly, alongside the recommendation to enable rotation, use a multi-Region key, and never delete the CMK before confirming no realm references it. |

---

---

## 8. The realm that needs more: keys that never leave the HSM *(experimental)*

Everything above decrypts the private key into pod memory and signs locally — the same exposure as
vanilla Keycloak while running, strictly better at rest. For most people that closes the finding.

One of Dana's realms belongs to a regulated customer whose contract says the signing key must never
exist in plaintext outside a hardware security module. For that realm there is a second mode —
shipped in v1 **marked experimental**, and the startup log says so. The mechanism that lets Keycloak
sign through KMS without a fork has no production mileage yet, and the mode has a throughput ceiling
that envelope mode does not. Dana reads that, decides one realm's worth of risk is acceptable, and
proceeds.

Dana creates an asymmetric CMK — one per realm key, because that is what "the key is the HSM object"
means:

```bash
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "Keycloak signing key — customer-b"
```

`ECC_NIST_P256` rather than RSA: inside KMS an EC signature is faster and cheaper than an RSA one,
and ES256 is understood by every relying party that matters. RSA native providers exist too, for
realms whose clients cannot do ES256.

Then Dana adds a `kms-ec-native` provider to the realm and pastes in the ARN. The extension calls
`kms:GetPublicKey`, derives the kid from the public key, mints a self-signed certificate by signing
it through `kms:Sign`, and publishes the result in JWKS. From the outside nothing is different: same
JWKS shape, same token format, same verification.

Inside, every token issuance is now a `kms:Sign` call. Keycloak never holds the private key, and
neither does the database — it holds an ARN.

The extension is explicit about what that costs, at the moment the provider is created:

```
WARN  [io.phasetwo.keycloak.kms] realm 'customer-b': native provider added
      key=arn:aws:kms:us-east-1:111122223333:key/9c4e… (ECC_NIST_P256, SIGN_VERIFY)
      *** NATIVE MODE IS EXPERIMENTAL IN THIS RELEASE. Envelope mode is the supported default. ***
      This CMK bills ~$1/month for as long as it exists, and every token issued by this realm
      costs one kms:Sign call (~$0.03 per 10,000) and adds ~5-15ms to the token endpoint.
      kms:Sign draws on a per-region asymmetric quota shared by your whole AWS account —
      check Service Quotas before pointing high-volume realms at this mode.
```

**Migration cannot target this mode, by design.** A key imported from a database spent years at rest
in plaintext; putting it inside an HSM afterwards keeps every cost of native mode and throws away
the one property it exists for. So the path is the two-step Dana already knows: migrate to envelope
mode (zero downtime, same kid), then rotate to a native provider — a new kid under standard
passive-key semantics, and material that has never existed outside AWS.

Dana uses native mode for one realm out of forty. That ratio is the point: it is a per-realm option,
not a cluster-wide posture, and the two modes coexist in one server.

---

## What this story deliberately does not include

- **A UI.** Configuration is server-level; per-realm actions are REST. Consistent with every other
  Phase Two extension, which ship no admin UI of their own.
- **Non-AWS backends.** The repo is named `keycloak-kms`, not `keycloak-aws-kms`, and the design
  keeps the seam for GCP KMS / Azure Key Vault / Vault Transit. AWS is the only implementation in v1.
- **EdDSA.** AWS KMS has no Ed25519 key spec, so native mode cannot support it at all. Envelope
  mode could, and it is a fast-follow there.
