#!/bin/bash
# Creates the CMKs the dev Keycloak expects. Runs once, when LocalStack is ready.
set -euo pipefail

echo "keycloak-kms: creating development CMKs"

# Envelope mode: one symmetric key for the whole server.
SYMMETRIC=$(awslocal kms create-key \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --description "Keycloak realm keys (development)" \
  --query 'KeyMetadata.KeyId' --output text)
awslocal kms create-alias --alias-name alias/keycloak-realm-keys --target-key-id "$SYMMETRIC"

# Native mode: one asymmetric key per realm key, so this is only a starting point.
EC=$(awslocal kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_NIST_P256 \
  --description "Keycloak native signing key (development)" \
  --query 'KeyMetadata.KeyId' --output text)
awslocal kms create-alias --alias-name alias/keycloak-native-ec --target-key-id "$EC"

RSA=$(awslocal kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec RSA_2048 \
  --description "Keycloak native RSA signing key (development)" \
  --query 'KeyMetadata.KeyId' --output text)
awslocal kms create-alias --alias-name alias/keycloak-native-rsa --target-key-id "$RSA"

echo "keycloak-kms: symmetric=$SYMMETRIC ec=$EC rsa=$RSA"
