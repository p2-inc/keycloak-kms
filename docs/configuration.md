# Configuration

## Server options

Set at startup, for the whole server.

| Option | Default | Meaning |
|---|---|---|
| `--spi-kms--provider` | *(none)* | Which backend: `aws`, or `local` for development. Nothing works until this is set. |
| `--spi-kms--aws--region` | `AWS_REGION`, then `AWS_DEFAULT_REGION` | Region of the KMS endpoint. No default — signing against the wrong region fails with an error that never mentions regions. |
| `--spi-kms--aws--key-id` | *(none)* | Default symmetric CMK for envelope mode: an ARN, a key id, or `alias/name`. |
| `--spi-kms--aws--endpoint` | derived from region | Override the endpoint URL. For LocalStack and tests. |
| `--spi-kms--aws--access-key-id` | *(none)* | Static credentials. Discouraged — see [aws-setup.md](aws-setup.md#3-credentials). |
| `--spi-kms--aws--secret-access-key` | *(none)* | |
| `--spi-kms--aws--session-token` | *(none)* | If the static credentials are temporary. |
| `--spi-kms--aws--role-arn` | *(none)* | Assume this role (`sts:AssumeRole`) with the server's own credentials and call KMS as the role. For a key in another account whose owner grants a role. When set it is the only credential source. See [aws-setup.md](aws-setup.md#assuming-a-role-in-the-keys-account). |
| `--spi-kms--aws--role-external-id` | *(none)* | The external id the role's trust policy requires. |
| `--spi-kms--aws--role-session-name` | `keycloak-kms` | Session name, shown in the key owner's CloudTrail. |
| `--spi-kms--aws--role-duration-seconds` | `3600` | Requested session length, 900 up to the role's maximum. Refreshed five minutes before expiry. |
| `--spi-kms--aws--sts-endpoint` | regional, from the region | Override the STS endpoint used with `role-arn`. For LocalStack and tests. |
| `--spi-kms--cache-ttl-seconds` | `300` | How long unwrapped material stays in memory. `0` disables caching, turning every signature into a KMS call. |
| `--spi-kms--default-for-new-realms` | `false` | Create new realms with KMS-backed key providers instead of the stock ones. |
| `--spi-kms--migrate-on-startup` | `false` | Migrate every realm at boot. Off by default; the per-realm REST endpoint is the supported path. |
| `--spi-kms--local--kek` | published dev key | `local` backend only. Base64 of a 16/24/32-byte AES key. |

Every option is also settable as an environment variable — Keycloak maps `--spi-a--b--c` to
`KC_SPI_A__B__C`:

```yaml
KC_SPI_KMS__PROVIDER: aws
KC_SPI_KMS__AWS__REGION: us-east-1
KC_SPI_KMS__AWS__KEY_ID: alias/keycloak-realm-keys
```

The environment form is confirmed on Keycloak 26.8.2, including on Phase Two hosted clusters, where
it is the only way to set server options. If your Keycloak version disagrees about the spelling,
pass the options on the command line instead; that form is stable across versions and is what the
integration tests use.

## Per-provider configuration

In the admin console under **Realm settings → Keys → Providers**, or via
`POST /admin/realms/{realm}/components`.

### Envelope providers

`kms-rsa-generated`, `kms-rsa-enc-generated`, `kms-hmac-generated`, `kms-aes-generated`

| Property | Notes |
|---|---|
| `priority` | As for any key provider. The highest-priority active key of an algorithm signs. |
| `enabled`, `active` | As for any key provider. Disabled providers make no KMS calls at all. |
| `algorithm` | RS256/384/512 and PS256/384/512 for RSA; HS256/384/512 for HMAC; RSA-OAEP for RSA-enc. |
| `keySize` | RSA only: 1024, 2048 (default), 3072, 4096. |
| `secretSize` | HMAC and AES only, in bytes. Defaults to 64 and 16. |
| `kmsKeyId` | Optional. Use a different CMK for this one provider — a per-tenant key, say. Falls back to `--spi-kms--aws--key-id`. |

Two values are written by the extension rather than by you:

- `kid` — pinned explicitly at creation, so it cannot drift if a future Keycloak changes how it
  derives one.
- `wrappedMaterial` — `kms://v1/<base64url>`, the KMS ciphertext. The `v1` is a format version, so
  a future change is a legible error rather than a decrypt failure that looks like a wrong key.

Neither appears in the admin API's component representation, because Keycloak builds that from the
properties a factory declares. Read `GET /realms/{realm}/kms/status` for the real state.

### Native providers

`kms-ec-native`, `kms-rsa-native` — see [native-mode.md](native-mode.md).

| Property | Notes |
|---|---|
| `kmsKeyId` | **Required.** ARN of an asymmetric `SIGN_VERIFY` CMK. There is no default and the extension will not create one. |
| `algorithm` | Must match the key's spec: ES256 for `ECC_NIST_P256`, ES384 for P384, ES512 for P521; RS*/PS* for `RSA_*`. |

## Caching

Unwrapped material is cached in memory keyed by `(realm, component, digest-of-ciphertext)` with the
configured TTL. One decrypt per key per process per TTL; everything after that signs at memory
speed.

Keying on the ciphertext rather than the component id means changing a provider's material makes
the old cache entry unreachable immediately — there is no window in which a rotated key keeps
signing with the material it just replaced, and nothing to invalidate.

Setting the TTL to `0` disables caching entirely. That is correct for the genuinely paranoid and
ruinous for everyone else: it puts a KMS round trip on every signature, which is the cost native
mode has, without native mode's benefit.

## Startup behaviour

The extension calls `kms:DescribeKey` once during `postInit` and **fails startup** if the key is
missing, disabled, of the wrong usage, or unreachable.

This is deliberate. A key-custody extension that starts anyway leaves realms serving from whatever
keys they have while the operator sees a healthy server and believes a control is in place. If you
have configured no default key — because every provider names its own, or you use only native mode
— the extension logs a warning and starts.
