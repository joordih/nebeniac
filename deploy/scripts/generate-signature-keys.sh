#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="${SCRIPT_DIR}/../../auth/keys/signatures"

if [[ -f "${KEY_DIR}/ed25519_private.pem" ]]; then
  echo "Keys already exist at ${KEY_DIR}. Delete them first if you want to regenerate."
  echo "WARNING: Regenerating keys invalidates all previously signed JARs."
  exit 1
fi

mkdir -p "${KEY_DIR}"

openssl genpkey -algorithm Ed25519 -out "${KEY_DIR}/ed25519_private.pem"
openssl pkey -in "${KEY_DIR}/ed25519_private.pem" -pubout -out "${KEY_DIR}/ed25519_public.pem"
openssl pkey -in "${KEY_DIR}/ed25519_private.pem" -pubout -outform DER -out "${KEY_DIR}/ed25519_public.der"

dd if="${KEY_DIR}/ed25519_public.der" bs=1 skip=12 2>/dev/null \
  | base64 -w0 | tr '+/' '-_' | tr -d '=' \
  > "${KEY_DIR}/public_key_base64url.txt"

echo "Keys generated in ${KEY_DIR}:"
ls -1 "${KEY_DIR}"
echo ""
echo "Next: run 'deploy/scripts/sync-e2ee-keys.sh' to distribute the public key to the plugin loader."
