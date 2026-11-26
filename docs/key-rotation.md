# Key rotation runbook (envelope mode)

How to rotate keys when the symmetric KMS key that protects realm key material is owned by someone
other than the Keycloak operator, typically a customer holding the key in their own AWS account.

Native mode is out of scope. See [native-mode.md](native-mode.md).

## Two layers, three procedures

Envelope mode has two layers of keys, and "rotation" can mean either one.

- **The CMK** is the customer's symmetric KMS key, the key-encryption key. It never leaves KMS.
- **Realm keys** are the RSA, HMAC and AES keys Keycloak signs and encrypts with. Their material is
  stored in component config as `kms://v1/…` ciphertext produced by the CMK.

| Procedure | When | Who acts | Keycloak changes | Token impact |
|---|---|---|---|---|
| [A. Rotate the CMK's backing material](#a-rotate-the-cmks-backing-material) | Routine, scheduled or on demand | Customer only | None | None |
| [B. Replace the CMK with a new key](#b-replace-the-cmk-with-a-new-key) | New key ID required: imported material, suspected compromise, account or region move, policy | Customer and operator | Yes | None if retired on schedule |
| [C. Rotate realm keys](#c-rotate-realm-keys-under-the-same-cmk) | Routine realm-key hygiene, or after A when policy requires re-encryption | Operator only | Yes | None if retired on schedule |

**Procedure A is the one to choose wherever it is allowed.** It needs no coordination and cannot
lock a realm out.

## Responsibilities

| Customer (key owner) | Keycloak operator |
|---|---|
| Creates the CMK and owns its key policy | Owns the Keycloak IAM role and its identity policy |
| Enables and schedules rotation | Owns `--spi-kms--aws--key-id` and per-provider `kmsKeyId` |
| Watches CloudTrail for `Decrypt` against the key | Creates, retires and deletes realm key providers |
| Disables and deletes retired keys, only after the operator confirms | Confirms when a retired key is no longer referenced |

### Cross-account keys

For Phase Two hosted customers who keep the key in their own account, the customer-facing version of
this runbook is [customer-managed-keys.md](customer-managed-keys.md).

When the CMK lives in the customer's account, two policies must both allow each call: the
customer's **key policy** must name the Keycloak role, and the role's **IAM policy** must name the
key. The statement from [aws-setup.md](aws-setup.md#2-iam) goes in both, with the principal and
resource adjusted.

Reference the key by **key ARN** everywhere: in `--spi-kms--aws--key-id` and in every `kmsKeyId`.
A bare `alias/name` resolves in the caller's account, not the customer's. An alias ARN would work,
but an alias can be retargeted, and retargeting has the same effect as changing the key
(see [why B is not a config change](#why-this-is-not-a-config-change)).

The customer may scope the key policy to their realms. Every ciphertext carries this encryption
context, and KMS logs it in CloudTrail on each call:

| Key | Value |
|---|---|
| `app` | always `keycloak` |
| `realm` | the realm's internal **id**, not its name |
| `kid` | the key id published in JWKS |
| `keyType` | `RSA`, `RSA_ENC`, `HMAC` or `AES` |

## Setup used by the commands below

```bash
KC=https://keycloak.example.com
REALM=customer-a
TOKEN=$(curl -s -X POST "$KC/realms/master/protocol/openid-connect/token" \
  -d client_id=admin-cli -d grant_type=password -d username=admin -d password="$ADMIN_PASSWORD" \
  | jq -r .access_token)
H=(-H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json")
```

Admin tokens expire after a minute by default. Refresh `TOKEN` between steps.

### Inventory: which keys exist and which CMK each one uses

```bash
# Every key provider in the realm: kid, priority, active/enabled, plaintext left
curl -s "${H[@]}" "$KC/realms/$REALM/kms/status" | jq

# The algorithm of each key (needed to rotate like-for-like)
curl -s "${H[@]}" "$KC/admin/realms/$REALM/keys" \
  | jq '.keys[] | {kid, algorithm, type, status, providerPriority}'

# Which CMK each envelope provider names. Empty means "the server default".
curl -s "${H[@]}" "$KC/admin/realms/$REALM/components?type=org.keycloak.keys.KeyProvider" \
  | jq '.[] | select(.providerId | startswith("kms-")) | {id, name, providerId, kmsKeyId: (.config.kmsKeyId[0] // "<server default>")}'
```

The status endpoint is the source of truth for kids and state. The admin components API omits
`kid` and the ciphertext, but it does show `kmsKeyId`, because that property is declared.

---

## A. Rotate the CMK's backing material

**Customer action only. Nothing changes in Keycloak.**

AWS KMS rotation replaces the cryptographic material behind a key while keeping its key ID, ARN,
aliases and policy. KMS keeps every previous version. Each ciphertext records the version that
produced it, so ciphertext sealed before the rotation keeps decrypting.

```bash
# Scheduled: every 90 to 2560 days (365 if the period is omitted)
aws kms enable-key-rotation --key-id <key-arn> --rotation-period-in-days 365

# On demand, in addition to or instead of the schedule
aws kms rotate-key-on-demand --key-id <key-arn>

# Confirm
aws kms get-key-rotation-status --key-id <key-arn>
aws kms list-key-rotations --key-id <key-arn>
```

**After rotation:** realm key material already in the database stays encrypted under the backing
material that sealed it. KMS handles this transparently. Only keys generated afterwards are sealed
under the new material. If the customer's policy requires existing material to be re-encrypted, run
[procedure C](#c-rotate-realm-keys-under-the-same-cmk) next. Procedure C creates new realm keys
rather than re-wrapping old ones, so it also replaces the signing material.

**Keys with imported material** (`Origin: EXTERNAL`, "bring your own key") do not support
automatic rotation. Check the current AWS documentation for whether on-demand rotation is available
for them. If it is not, use procedure B.

---

## B. Replace the CMK with a new key

Use this when the key ID itself has to change.

### Why this is not a config change

Every `Decrypt` the extension sends names a key: the provider's `kmsKeyId` if it has one,
otherwise the server default `--spi-kms--aws--key-id` **as configured now**. KMS rejects a decrypt
that names a different key from the one that sealed the ciphertext.

So if you point the default at the new key, or retarget an alias the default uses, every existing
provider without its own `kmsKeyId` starts failing with `IncorrectKeyException`. It fails silently
at first. Cached material keeps serving until the cache TTL expires (five minutes by default) or a
pod restarts, and then the realm cannot issue tokens.

The procedure below avoids that by pinning every existing provider to the old key **before**
anything changes.

### B1. Customer: create the new key and grant access

Create a symmetric `ENCRYPT_DECRYPT` key, multi-Region if Keycloak runs in more than one region
(see [aws-setup.md](aws-setup.md#decide-multi-region-now)). Add the Keycloak role to its key
policy with `kms:Encrypt`, `kms:Decrypt` and `kms:DescribeKey`, conditioned on
`kms:EncryptionContext:app = keycloak`. Enable automatic rotation on it now, so the next rotation
can be procedure A.

Send the operator the new **key ARN**. Leave the old key enabled and its policy unchanged.

### B2. Operator: allow both keys in the role's IAM policy

Add the new key ARN to the `Resource` list of the Keycloak role's KMS statement. Keep the old one.

Optional check, from a shell holding the Keycloak role:

```bash
aws kms describe-key --key-id <new-key-arn>
aws kms encrypt --key-id <new-key-arn> --plaintext fileb://<(echo probe) \
  --encryption-context app=keycloak,realm=probe,kid=probe,keyType=RSA
```

### B3. Operator: pin existing providers to the old key

For every realm, set `kmsKeyId` to the **old key ARN** on each envelope provider that does not
already name a key. Providers that already name the old key need nothing.

Editing `kmsKeyId` on an existing provider does not regenerate it. The extension carries the
stored ciphertext and kid forward, and only changes which key ID the next decrypt names.

```bash
OLD_KEY=arn:aws:kms:us-east-1:111122223333:key/<old-key-id>

for REALM in $(curl -s "${H[@]}" "$KC/admin/realms" | jq -r '.[].realm'); do
  curl -s "${H[@]}" "$KC/admin/realms/$REALM/components?type=org.keycloak.keys.KeyProvider" \
  | jq -c '.[] | select(.providerId | test("^kms-(rsa|rsa-enc|hmac|aes)-generated$"))
               | select((.config.kmsKeyId[0] // "") == "")' \
  | while read -r c; do
      id=$(jq -r .id <<<"$c")
      jq --arg k "$OLD_KEY" '.config.kmsKeyId = [$k]' <<<"$c" \
        | curl -s -o /dev/null -w "$REALM $id %{http_code}\n" -X PUT "${H[@]}" \
            "$KC/admin/realms/$REALM/components/$id" --data-binary @-
    done
done
```

Every line should end in `204`. Then re-run the inventory: every `kms-*-generated` provider should
name a key, and the kids in `/kms/status` must be unchanged.

The same edit works in the admin console. Open **Realm settings → Keys → Providers**, open the
provider, fill in **KMS key**, and save.

### B4. Operator: prove the pins before going further

Pinning takes effect on the next cache miss, so a wrong ARN would not show up yet. Force a cold
read: restart one Keycloak pod, or wait longer than `--spi-kms--cache-ttl-seconds`. Then list each
realm's keys **through that pod**:

```bash
curl -s "${H[@]}" "$KC/admin/realms/$REALM/keys" | jq '.keys[] | {kid, algorithm, status}'
```

Every kid from the inventory should appear. A `500` or a missing kid means a pin is wrong. Fix it
before continuing. The server log names the provider and the KMS error.

### B5. Operator: make the new key the default (shared-default deployments only)

Skip this step if the customer's key is used only through per-provider `kmsKeyId` values and the
server default belongs to some other key.

Otherwise set `--spi-kms--aws--key-id` (or `KC_SPI_KMS__AWS__KEY_ID`) to the new key ARN and do a
rolling restart. Each pod runs `DescribeKey` against the new key at startup and refuses to start if
the key is missing, disabled, asymmetric or unreachable. A pod that fails here has changed nothing.
Roll it back to the old value and fix the grant.

### B6. Operator: generate new realm keys under the new key

For each key type present in the realm, create a new provider that names the new key and outranks
the current one. Match the algorithm of the key being replaced. Read it from the inventory's
`/admin/realms/{realm}/keys` output.

```bash
NEW_KEY=arn:aws:kms:us-east-1:111122223333:key/<new-key-id>
REALM_ID=$(curl -s "${H[@]}" "$KC/admin/realms/$REALM" | jq -r .id)
STAMP=$(date +%Y-%m)

new_key() {  # providerId algorithm priority
  jq -n --arg p "$1" --arg a "$2" --arg pr "$3" --arg k "$NEW_KEY" \
        --arg parent "$REALM_ID" --arg n "$1 ($STAMP)" \
    '{name:$n, providerId:$p, providerType:"org.keycloak.keys.KeyProvider", parentId:$parent,
      config:{priority:[$pr], algorithm:[$a], kmsKeyId:[$k]}}' \
  | curl -s -w "%{http_code}\n" -X POST "${H[@]}" \
      "$KC/admin/realms/$REALM/components" --data-binary @-
}

# One line per key in the inventory. Priority = current highest for that type + 100.
new_key kms-rsa-generated     RS256    200
new_key kms-rsa-enc-generated RSA-OAEP 200
new_key kms-hmac-generated    HS512    200
new_key kms-aes-generated     AES      200
```

Each call should return `201`. The extension generates the material, seals it under the new key,
and decrypts it back before saving. A key the new CMK cannot round-trip is rejected with a `400`
and never stored.

Confirm in `/kms/status` that each new kid is active at the top priority for its type. Check that
the new signing kid is published, then sign in to the realm once and decode the token header to
confirm it carries the new kid:

```bash
curl -s "$KC/realms/$REALM/protocol/openid-connect/certs" | jq '.keys[].kid'
```

**Why not `POST /realms/{realm}/kms/rotate`:** that endpoint always uses the server default key
and each factory's default algorithm. HMAC defaults to HS256, while Keycloak signs refresh tokens
with an HS512 key, so a rotated HS256 key would not take over. Use the endpoint only when the
server default is the intended key and the realm's keys use the defaults, which are RS256,
RSA-OAEP and AES.

### B7. Operator: retire the old realm keys

Retire in the order Keycloak expects, so that nothing already issued stops verifying early.

1. **Make the old providers passive** by setting `active` to false. They stop signing and still
   verify.
2. **Wait** for the longest-lived thing they signed to expire. That is the largest of the access
   token lifespan, the SSO session max, and the offline session max if offline tokens are used.
   Refresh and offline tokens are signed with the HMAC key, so its wait is usually the longest.
3. **Disable the old providers** by setting `enabled` to false. A disabled provider makes no KMS
   calls at all. Anything still signed by those kids now fails, and users re-authenticate.
4. **Delete the old providers** once nothing has complained.

```bash
# Steps 1 and 3: set active (or enabled) to false on one provider
c=$(curl -s "${H[@]}" "$KC/admin/realms/$REALM/components/$OLD_COMPONENT_ID")
jq '.config.active = ["false"]' <<<"$c" \
  | curl -s -w "%{http_code}\n" -X PUT "${H[@]}" \
      "$KC/admin/realms/$REALM/components/$OLD_COMPONENT_ID" --data-binary @-

# Step 4
curl -s -w "%{http_code}\n" -X DELETE "${H[@]}" \
  "$KC/admin/realms/$REALM/components/$OLD_COMPONENT_ID"
```

When every provider that named the old key is disabled or deleted, tell the customer the old key
is no longer referenced. Remove its ARN from the role's IAM policy.

### B8. Customer: decommission the old key

1. **Check CloudTrail.** Look for `Decrypt` events against the old key ARN since step B7 finished.
   Each event's `requestParameters.encryptionContext` names the realm id and kid that made the
   call. Anything still appearing is a provider that was missed. Hand it back to the operator.
2. **Disable the key.** This is reversible with `aws kms enable-key`. Leave it disabled for a soak
   period long enough to cover a full restart of every Keycloak pod.
3. **Schedule deletion** with the longest waiting period, 30 days. It can be cancelled with
   `aws kms cancel-key-deletion` until it completes.

**Deletion is permanent, and backups depend on the key.** Every database backup taken before
rotation holds realm keys sealed under the old key. Once the key is deleted, restoring such a
backup produces realms that cannot issue tokens. Keep the old key, disabled, for as long as those
backups are retained.

### Rollback

| Failed at | Undo |
|---|---|
| B3 or B4 | Clear the `kmsKeyId` you set. Only possible while the default still points at the old key. |
| B5 | Set the default back to the old key ARN and restart. Pinned providers are unaffected either way. |
| B6 | Delete the new providers. The old ones are still active underneath them. |
| B7 step 1 | Set `active` back to true on the old providers. |
| B7 step 3 | Set `enabled` back to true. |
| B7 step 4 | No undo. Deleted providers are gone. |
| B8 step 2 | `aws kms enable-key`. |
| B8 step 3 | `aws kms cancel-key-deletion`, then `aws kms enable-key`, before the waiting period ends. |

---

## C. Rotate realm keys under the same CMK

**Operator action only.** The CMK does not change. This generates new realm key material, so the
kids change, and retires the old material.

Follow [B6](#b6-operator-generate-new-realm-keys-under-the-new-key) and
[B7](#b7-operator-retire-the-old-realm-keys) with these differences.

- **Which key to name.** Set `kmsKeyId` to the realm's current CMK ARN, or drop `kmsKeyId` from the
  request to use the server default.
- **The shortcut.** When the server default is the right key and the realm uses default
  algorithms, this does the same thing as B6 for one key type:

  ```bash
  curl -s -X POST "${H[@]}" "$KC/realms/$REALM/kms/rotate?keyType=RSA" | jq
  ```

  Valid types are `RSA`, `RSA_ENC`, `HMAC` and `AES`. Do not use it for HMAC on a realm that signs
  with HS512.
- **No KMS cleanup.** Skip the hand-off to the customer and B8. The CMK stays in use.

---

## Suspected CMK compromise

Assume the realm keys are exposed too. Someone who can call `Decrypt` on the CMK and has read the
database can recover them. Run procedure B with two changes:

- **Skip the passive phase.** In B7, disable the old providers right away. Every session and
  token signed with the old keys becomes invalid, and users sign in again. That is the point.
- **Lock the old key down first.** Before B3, ask the customer to remove `kms:Decrypt` on the old
  key from every principal except the Keycloak role. Disabling the key outright would stop every
  realm until B6 is complete.

---

## Errors you may see

| KMS error in the Keycloak log | Meaning | Fix |
|---|---|---|
| `IncorrectKeyException` | The decrypt named a different key from the one that sealed the material. Almost always an unpinned provider after the default or an alias changed. | Pin that provider's `kmsKeyId` to the key that sealed it, or restore the previous default. |
| `AccessDeniedException` | The key policy or the role's IAM policy does not allow the call. The message names the action. | Grant it in whichever policy is missing it. Cross-account calls need both. |
| `InvalidCiphertextException` | The encryption context does not match, or the ciphertext was edited. | Check that the component was not copied between realms or edited by hand. |
| `DisabledException` | The key is disabled. | `aws kms enable-key`. |
| `NotFoundException` | No such key in this region. Common causes are a wrong ARN, a wrong region, or a multi-Region key with no replica here. | Correct the ARN or region, or replicate the key. |
| `KMSInvalidStateException` | The key is pending deletion. | `aws kms cancel-key-deletion`, then `aws kms enable-key`. |
| Startup refuses: "cannot reach AWS KMS key" | The default key fails `DescribeKey`. | Fix the grant or the ARN. No realm state has changed. |
