# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it through GitHub's private vulnerability reporting — the **Security** tab of this
repository, then **Report a vulnerability**. If you cannot use that, email
[support@phasetwo.io](mailto:support@phasetwo.io) with `keycloak-kms security` in the subject.

Please include the extension version or commit, the Keycloak version, which mode is in use
(envelope or native), and enough detail to reproduce. We will acknowledge receipt and tell you
whether we consider it a vulnerability and what we intend to do about it.

## Scope

This extension exists to keep realm signing keys out of the database, so we are particularly
interested in anything that undermines that:

- Key material — private keys, HMAC or AES secrets — reaching the database, a log, an error
  response, or an admin API representation in plaintext.
- A `wrappedMaterial` ciphertext that decrypts outside the realm, kid and key type it was sealed
  against. The encryption context is meant to make that a KMS-enforced impossibility; a way around
  it is a vulnerability.
- Any path where the extension is configured but a realm is nonetheless served by database-backed
  keys, silently. Failing closed is a design property, not an implementation detail.
- Privilege errors on the REST resource: `/realms/{realm}/kms` reads require `view-realm` and
  writes require `manage-realm`, scoped to the realm in the path.
- Signature forgery or algorithm confusion in native mode's JCA path.

## Not in scope

- **`LocalKmsProvider`** (`--spi-kms--provider=local`) offers no protection against anyone who can
  read the Keycloak configuration. That is documented, logged loudly at every startup, and exists
  only for tests and the `docker compose` dev environment. Reports that it is insecure are working
  as intended.
- **Everything in `docker/` and `docker-compose.yml`** — admin/admin, LocalStack, no TLS. It is a
  dev environment, not a deployment example.
- **Plaintext that migration left behind.** Migration encrypts key material going forward; it
  cannot un-disclose material that already sat in the database, its backups and its replicas. This
  is stated in [docs/migration.md](docs/migration.md), and the fix is to rotate.
- **Deleting or disabling the CMK breaks every realm.** The CMK is deliberately the root of trust;
  see [docs/aws-setup.md](docs/aws-setup.md) for the alarms we recommend.
- Findings from a scanner against the `provided` dependency versions in `pom.xml`. Nothing but the
  extension's own classes ships in the jar — Keycloak supplies Jackson and Bouncy Castle at
  runtime, and its versions are what run.

## Supported versions

Fixes go onto `main`, against the Keycloak version in `pom.xml`. Native mode is **experimental**;
it gets security fixes, but it has no production mileage and should not be treated as hardened.
