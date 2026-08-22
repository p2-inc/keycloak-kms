#!/usr/bin/env bash
# Migrate the 'dev' realm's keys into the KMS and show what changed.
#
# Run `make start` first. This is the walkthrough from docs/migration.md, as a script.
set -euo pipefail

BASE="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-dev}"

token() {
  curl -sf -X POST "$BASE/realms/master/protocol/openid-connect/token" \
    -d client_id=admin-cli -d grant_type=password \
    -d "username=${KEYCLOAK_ADMIN:-admin}" -d "password=${KEYCLOAK_ADMIN_PASSWORD:-admin}" \
    | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'
}

TOKEN=$(token)
[ -n "$TOKEN" ] || { echo "could not authenticate against $BASE" >&2; exit 1; }

echo "== before =="
curl -sf "$BASE/realms/$REALM/kms/status" -H "Authorization: Bearer $TOKEN"
echo

echo "== JWKS before =="
BEFORE=$(curl -sf "$BASE/realms/$REALM/protocol/openid-connect/certs")
echo "$BEFORE"
echo

echo "== migrating =="
curl -sf -X POST "$BASE/realms/$REALM/kms/migrate" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json'
echo

echo "== after =="
curl -sf "$BASE/realms/$REALM/kms/status" -H "Authorization: Bearer $TOKEN"
echo

echo "== JWKS after =="
AFTER=$(curl -sf "$BASE/realms/$REALM/protocol/openid-connect/certs")
echo "$AFTER"
echo

# The point of the exercise: the same kids, still published.
echo "== kids before / after =="
echo "$BEFORE" | grep -o '"kid":"[^"]*"' | sort
echo "---"
echo "$AFTER"  | grep -o '"kid":"[^"]*"' | sort
echo
echo "Identical kid lists mean every token already issued still verifies."
echo "The legacy providers are deactivated but still hold plaintext — see the Keycloak log for"
echo "the exact components to delete, or re-run with ?deleteLegacy=true."
