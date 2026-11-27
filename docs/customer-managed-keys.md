# Customer-managed keys on Phase Two hosted Keycloak

How to protect your realm's signing and encryption keys with a KMS key that lives in **your** AWS
account, and how to rotate it.

Phase Two never holds your KMS key. You grant our Keycloak service role permission to use it, scoped
to your realms, and you can revoke that permission at any time.

## How it works

Your realm's keys are the RSA, HMAC and AES keys Keycloak uses to sign tokens and encrypt data. We
store them in our database only as ciphertext produced by your KMS key. To use a key, a Keycloak pod
calls `kms:Decrypt` on your key, from our AWS account, and holds the result in memory for a few
minutes.

| | You | Phase Two |
|---|---|---|
| The KMS key | Create, own, rotate, disable, delete | Never holds it. Uses it only as your key policy allows. |
| Key policy | Grant our role, scoped to your realm ids | Tell you the role ARN and your realm ids |
| Realm key providers | Optional: create and retire them yourself with realm admin access | Configure your realm to use your key. Rotate realm keys on request. |
| Audit | CloudTrail in your account shows every call we make | Read-only status endpoint for your realm |

Every ciphertext is bound to an **encryption context** that KMS checks on every call and logs in
CloudTrail:

| Key | Value |
|---|---|
| `app` | always `keycloak` |
| `realm` | your realm's internal id, which we give you. It is not the realm name. |
| `kid` | the key id published in your realm's JWKS |
| `keyType` | `RSA`, `RSA_ENC`, `HMAC` or `AES` |

Your key policy pins `realm` to your realm ids. Our service role serves every tenant on the cluster.
That pin is what stops anyone from using your key on behalf of another realm, including a mistake on
our side or an administrator of another tenant. Do not leave it out.

## Requirements

- **Region.** The key must be in the same region as your Keycloak cluster. A multi-Region key
  works if it has a replica in that region. We tell you the region during onboarding.
- **Failover to another region.** If your realm may ever run in a second region, create the key
  as multi-Region (`--multi-region`) and replicate it there **before onboarding**. Ciphertext
  sealed under a single-Region key can only be decrypted in that region, and converting later means
  re-encrypting every realm key. Grant the replica the same policy statements, and send us both
  ARNs.
- **Key type.** Symmetric, `ENCRYPT_DECRYPT`, `SYMMETRIC_DEFAULT`. Asymmetric keys are a different
  feature.
- **Referenced by key ARN.** We store the full key ARN against your realm. Aliases in your account
  are not visible to ours.

## Dedicated clusters

On a cluster that serves only your realms, two things can be simpler:

- **Your key can be the cluster's default key.** Every KMS-backed provider on the cluster then uses
  it, including ones created later, and nothing has to be set per provider. The `realm` condition
  is still worth keeping.
- **You can grant a role instead of editing the key policy.** Create a role in your account with
  the `kms:Encrypt`/`kms:Decrypt` (with `app=keycloak`) and `kms:DescribeKey` permissions on your
  key, and a trust policy naming our Keycloak role and an external id we agree with you. We
  configure the cluster to assume it ([aws-setup.md](aws-setup.md#assuming-a-role-in-the-keys-account)).
  Revoking is then a change to that role alone.

With your key as the cluster's default, revoking access affects the whole cluster, not one realm.
See [revoking access](#revoking-access).

## Onboarding

### 1. You: create the key

```bash
aws kms create-key \
  --region <cluster-region> \
  --description "Phase Two Keycloak realm keys" \
  --key-usage ENCRYPT_DECRYPT --key-spec SYMMETRIC_DEFAULT

aws kms enable-key-rotation --key-id <key-id> --rotation-period-in-days 365
```

### 2. You: grant our role, scoped to your realms

We send you two values: our Keycloak role ARN, and the internal id of each of your realms. Add the
statements below to the key policy. Keep your existing administrative statements. A policy that
contains only these would lock you out of your own key.

```json
{
  "Sid": "PhaseTwoKeycloakUse",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<phase-two-account-id>:role/<phase-two-keycloak-role>" },
  "Action": ["kms:Encrypt", "kms:Decrypt"],
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:EncryptionContext:app": "keycloak",
      "kms:EncryptionContext:realm": ["<realm-id-1>", "<realm-id-2>"]
    }
  }
},
{
  "Sid": "PhaseTwoKeycloakDescribe",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::<phase-two-account-id>:role/<phase-two-keycloak-role>" },
  "Action": "kms:DescribeKey",
  "Resource": "*"
}
```

`DescribeKey` is in a separate statement because it carries no encryption context, so the
conditions above would always deny it. It reveals only the key's metadata.

Adding a realm later means adding its id to the list.

### 3. You: send us the key ARN

Open a support request with the key ARN and the realms it should protect.

### 4. Phase Two: move your realm onto your key

We create new key providers for each key type in your realm, sealed under your key, and promote
them above the current ones. Before saving each key, we decrypt it again with your key to prove the
round trip works. New tokens are signed with the new keys immediately. The previous keys keep
verifying tokens already issued. We retire them on the schedule described in
[retiring old keys](#retiring-old-keys).

### 5. You: verify

In CloudTrail, in the key's region, you should see `Encrypt` and `Decrypt` calls from our role.
Each call's `requestParameters.encryptionContext` shows your realm id and the kid. After onboarding,
expect roughly one `Decrypt` per key, per Keycloak pod, every five minutes.

With realm admin access you can also check which key protects each provider:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://<your-keycloak>/admin/realms/<realm>/components?type=org.keycloak.keys.KeyProvider" \
  | jq '.[] | select(.providerId | startswith("kms-")) | {name, kmsKeyId: .config.kmsKeyId[0]}'
```

---

## Rotation

### Routine: rotate the key material

**You do this alone. Tell us nothing.**

```bash
aws kms enable-key-rotation --key-id <key-arn> --rotation-period-in-days 365   # scheduled
aws kms rotate-key-on-demand --key-id <key-arn>                                # immediately
aws kms list-key-rotations --key-id <key-arn>                                  # confirm
```

AWS replaces the material behind the key and keeps its ARN, its policy and every previous version.
Your realm keys stay encrypted under the version that sealed them, and KMS decrypts them
transparently. Keys created after the rotation are sealed under the new material.

If your policy requires existing keys to be re-encrypted after a rotation, follow it with a
[realm key rotation](#realm-key-rotation).

Keys with imported material (`Origin: EXTERNAL`) do not support automatic rotation. Check the
current AWS documentation for on-demand support. If it is not available, replace the key instead.

### Replacing the key with a new one

Use this when the key ARN itself has to change. Typical reasons are imported material, a suspected
compromise, or a move to another account. **Your old key must stay enabled until step 4.**

1. **You:** create the new key in the same region, with the same two policy statements. Enable
   automatic rotation on it.
2. **You:** open a support request with the new key ARN.
3. **Phase Two:** create new realm keys under the new key, then retire the keys that used the old
   one on the [standard schedule](#retiring-old-keys). We tell you when the old key is no longer
   referenced, and on what date.
4. **You:** check CloudTrail for `Decrypt` calls on the old key since that date. There should be
   none. Then disable the old key. Disabling is reversible with `aws kms enable-key`.
5. **You:** schedule deletion of the old key only after our backup retention period has passed
   from the date in step 3. See [backups](#backups-and-key-deletion).

### Realm key rotation

This generates new signing and encryption keys for your realm under your current KMS key. The kids
in your JWKS change, and your KMS key stays the same.

- **On request.** Open a support request. We run it and retire the old keys on the standard
  schedule.
- **Self-service.** With realm admin access, add a provider under **Realm settings → Keys →
  Providers** and set **KMS key** to your key ARN. Use the same type and algorithm as the key it
  replaces, and a higher priority. Then retire the old provider on the schedule below.

Do not leave **KMS key** blank on a provider you create yourself. A blank value means our default
key, not yours.

### Retiring old keys

Old realm keys are retired in stages so that nothing already issued stops working early.

1. **Passive.** The old key stops signing new tokens but still verifies existing ones. This happens
   immediately.
2. **Disabled.** This happens after the longest-lived thing it signed has expired. That is the
   longest of your access token lifespan, your SSO session max, and your offline session max if you
   use offline tokens.
3. **Deleted.** This happens after a further quiet period.

You can ask for a shorter schedule. Anything still signed by a disabled key stops working, and those
users sign in again.

---

## Revoking access

Removing the policy statements, or disabling the key, is your kill switch. It needs nothing from
us.

- **Within about five minutes**, which is our key cache lifetime, every Keycloak pod loses the
  ability to use your realm's keys. Your realm then cannot issue tokens, and sign-ins fail.
- **Access tokens already issued stay valid until they expire.** Applications verify them with
  public keys they have already fetched, and no KMS call is involved. Revocation stops new tokens.
  It does not recall old ones.
- **Other tenants are unaffected.**
- **On a dedicated cluster where your key is the default**, Keycloak also checks the key when it
  starts, and refuses to start if it cannot reach it. Any restart while access is revoked, ours
  for maintenance or a configuration change, leaves the cluster down rather than running without
  your key. Restoring access lets it start again.
- **Restoring is instant.** Put the statements back or re-enable the key. Your realm recovers on the
  next cache refresh, with no action from us and no change of keys.

## Suspected compromise

If you believe your KMS key has been misused, assume your realm keys are exposed. Contact support,
and replace the key as above, with two differences:

- We disable the old realm keys immediately rather than waiting. Every existing session and token
  is invalidated, and users sign in again.
- While the new keys are prepared, restrict `kms:Decrypt` on the old key to our role only. Do not
  disable it until we confirm the new keys are in place, or your realm stops issuing tokens in the
  meantime.

## Backups and key deletion

Our database backups contain your realm keys sealed under whichever KMS key was current when the
backup was taken. If you delete a key, any backup that depends on it can no longer restore your
realm.

**Keep a retired key disabled, not deleted, until our backup retention period has passed.** Then
schedule deletion with the 30-day waiting period. Deletion is permanent once that period ends.

## What not to do

- **Do not delete the key, or schedule its deletion, without the steps above.** Your realm becomes
  permanently unrecoverable from any backup that depends on it.
- **Do not remove the `realm` condition** from the key policy to save effort when adding realms.
- **Do not reference the key by alias** in anything you send us.
