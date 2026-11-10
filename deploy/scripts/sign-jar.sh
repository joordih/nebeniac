#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

if [ $# -ne 1 ]; then
    echo -e "${RED}[ERROR]${NC} Usage: $0 <path-to-jar>"
    echo ""
    echo "Example:"
    echo "  $0 /path/to/plugin-encrypted.jar"
    exit 1
fi

JAR_FILE="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRIVATE_KEY="${SCRIPT_DIR}/../../auth/keys/signatures/ed25519_private.pem"

if [ ! -f "${JAR_FILE}" ]; then
    echo -e "${RED}[ERROR]${NC} JAR file not found: ${JAR_FILE}"
    exit 1
fi

if [ ! -f "${PRIVATE_KEY}" ]; then
    echo -e "${RED}[ERROR]${NC} Private key not found: ${PRIVATE_KEY}"
    echo ""
    echo "Generate keys first with:"
    echo "  ./deploy/scripts/generate-signature-keys.sh"
    exit 1
fi

echo "=========================================="
echo "  JAR Signature Tool (Ed25519)"
echo "=========================================="
echo ""
echo -e "${GREEN}[INFO]${NC} Signing JAR: ${JAR_FILE}"

TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

echo -e "${GREEN}[INFO]${NC} Extracting JAR..."
cd "${TEMP_DIR}"
jar xf "$(realpath "${JAR_FILE}")"

echo -e "${GREEN}[INFO]${NC} Calculating JAR hash..."

find . -type f \( -name "*.encrypted" -o -name "*.iv" -o -name "plugin.yml" \) | sed 's|^\./||' | sort > files.txt

{
    while IFS= read -r file; do
        echo -n "${file}"
        cat "${file}"
    done < files.txt
} | sha256sum | cut -d' ' -f1 > jar_hash.txt

JAR_HASH=$(cat jar_hash.txt)
echo -e "${YELLOW}[DEBUG]${NC} JAR Hash: ${JAR_HASH}"

echo "${JAR_HASH}" | xxd -r -p > jar_hash.bin

echo -e "${GREEN}[INFO]${NC} Signing with Ed25519..."
openssl pkeyutl -sign -inkey "${PRIVATE_KEY}" -in jar_hash.bin -out signature.bin

SIGNATURE_BASE64URL=$(base64 -w0 signature.bin | tr '+/' '-_' | sed 's/=*$//')

echo -e "${YELLOW}[DEBUG]${NC} Signature (Base64URL): ${SIGNATURE_BASE64URL}"

echo -e "${GREEN}[INFO]${NC} Adding signature to JAR..."
echo -n "${SIGNATURE_BASE64URL}" > NEBENIAC.SIG

echo -e "${GREEN}[INFO]${NC} Repackaging JAR..."
jar cf "$(realpath "${JAR_FILE}")" *

cd - > /dev/null

echo ""
echo -e "${GREEN}[SUCCESS]${NC} JAR signed successfully!"
echo ""
echo "Signed JAR: ${JAR_FILE}"
echo "Signature added: NEBENIAC.SIG"
echo ""
echo -e "${GREEN}✓${NC} Done!"
