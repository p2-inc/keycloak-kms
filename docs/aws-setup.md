# AWS setup

Everything this extension needs on the AWS side, and the decisions that are expensive to change
later.

## 1. The key

One symmetric KMS key protects realm key material for the whole cluster.

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

### Decide multi-Region now

If Keycloak runs in more than one region — now or plausibly later — create a **multi-Region** key
(`--multi-region`) and replicate it into each region:

```bash
aws kms create-key --multi-region --key-usage ENCRYPT_DECRYPT --key-spec SYMMETRIC_DEFAULT
aws kms replicate-key --key-id mrk-<id> --replica-region eu-west-1
```

A single-Region key means every `Decrypt` from a remote region crosses the internet, and adds that
latency to every cold key load. Converting afterwards is not a setting — it means re-encrypting
every realm's material under a new key.

### Automatic rotation is safe to enable

```bash
aws kms enable-key-rotation --key-id alias/keycloak-realm-keys
```

KMS keeps previous backing keys, so ciphertext written before a rotation still decrypts. Nothing in
Keycloak needs to know, and no realm needs re-encrypting.

## 2. IAM

Steady-state Keycloak needs three actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "KeycloakRealmKeys",
    "Effect": "Allow",
    "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
    "Resource": "arn:aws:kms:us-east-1:111122223333:key/<key-id>",
    "Condition": {
      "StringEquals": { "kms:EncryptionContext:app": "keycloak" }
    }
  }]
}
```

`kms:DescribeKey` is used once at startup for the fail-fast check. `kms:Encrypt` is used only when
a key is generated, migrated or rotated — a hardened deployment can split the policy so that
running pods hold `Decrypt` and `DescribeKey` only, and an operator role holds `Encrypt` for the
migration window.

### The encryption-context condition is load-bearing

The extension binds every ciphertext to `{app, realm, kid, keyType}`. KMS authenticates that map,
so a `wrappedMaterial` value copied out of realm A's config and pasted into realm B's will not
decrypt — the realm it was sealed against no longer matches.

The condition above makes it a **KMS-enforced** property rather than something this code promises.
Add these too if you want the binding enforced by policy rather than convention:

```json
"Condition": {
  "StringEquals": { "kms:EncryptionContext:app": "keycloak" },
  "ForAnyValue:StringEquals": { "kms:EncryptionContextKeys": ["realm", "kid", "keyType"] }
}
```

### Native mode needs a separate statement

Sign-in-KMS keys are asymmetric, carry no encryption context, and are named individually:

```json
{
  "Effect": "Allow",
  "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"],
  "Resource": [
    "arn:aws:kms:us-east-1:111122223333:key/<customer-b-signing-key>"
  ]
}
```

## 3. Credentials

No access keys. The extension resolves credentials in this order and logs which source won:

| Order | Source | Detected by |
|---|---|---|
| 1 | Extension config | `--spi-kms--aws--access-key-id` / `--secret-access-key` |
| 2 | Environment | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| 3 | EKS Pod Identity | `AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` |
| 4 | ECS task role | `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` |
| 5 | IRSA | `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE` (STS `AssumeRoleWithWebIdentity`) |
| 6 | EC2 instance profile | IMDSv2 |

Temporary credentials are refreshed through whichever source produced them, five minutes before
they expire.

```
INFO  [io.phasetwo.keycloak.kms.aws.credentials.AwsCredentialsProviderChain]
      AWS credentials resolved from web-identity (ASIAEXAMPLE)
```

### EKS

An IRSA annotation on the service account and nothing else:

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/keycloak-kms
```

The role's trust policy must name the cluster's OIDC provider and this service account. If the
projected token is missing or the trust policy does not match, the startup error says so rather
than falling through to the next source silently.

### Static keys

Supported, documented, and discouraged: storing a long-lived AWS secret in the Keycloak
configuration in order to protect keys in the Keycloak database moves the problem rather than
solving it. Use it only where there is genuinely no role to assume.

## 4. Operating it

| Concern | What to do |
|---|---|
| **Losing the CMK is unrecoverable** | It is the root of trust for every realm's keys. Set a 30-day deletion window and alarm on `ScheduleKeyDeletion` and `DisableKey` in CloudTrail. Nothing in this extension can recover from its loss. |
| Cost | One CMK is $1/month. `Decrypt` is $0.03 per 10,000 requests and happens once per realm per pod per cache TTL. Forty realms across three pods is roughly 35,000 calls a month — about ten cents. |
| Latency | None on the token path. KMS is touched only on a cache miss (single-digit milliseconds, region-local). Signing is in-process. |
| KMS unreachable | Keys already unwrapped keep serving until their TTL expires. A cold pod cannot serve those realms and fails rather than regenerating a database-backed key. |
| CMK disabled | Every realm using it loses its keys once caches expire. This is the failure mode to alarm on. |
| Verifying the control | `GET /realms/{realm}/kms/status` reports `plaintextRemains` per realm. That is the query to put in an audit runbook. |

## 5. Non-AWS backends

The `kms` SPI is deliberately backend-agnostic; `aws` is simply the only implementation shipped.
A GCP KMS, Azure Key Vault or Vault Transit backend is an implementation of `KmsProvider` plus a
factory — see `io.phasetwo.keycloak.kms.local.LocalKmsProvider` for the smallest complete example.
