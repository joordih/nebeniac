#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

KEYS_DIR="/app/keys"
PUBLIC_KEY_FILE="${KEYS_DIR}/server_public_key.json"
PLUGIN_DIR="/app/loader"
RESOURCES_DIR="${PLUGIN_DIR}/src/main/resources"
OUTPUT_DIR="/out"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Plugin Loader Builder${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

echo -e "${BLUE}[STEP 1]${NC} Waiting for E2EE public key..."
/app/wait-for-key.sh
if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Failed waiting for public key"
    exit 1
fi

echo -e "${BLUE}[STEP 2]${NC} Copying public key to plugin resources..."
mkdir -p "${RESOURCES_DIR}"
cp "${PUBLIC_KEY_FILE}" "${RESOURCES_DIR}/server_public_key.json"

if [ -f "${RESOURCES_DIR}/server_public_key.json" ]; then
    echo -e "${GREEN}[SUCCESS]${NC} Public key copied to: ${RESOURCES_DIR}/server_public_key.json"
    ls -la "${RESOURCES_DIR}/server_public_key.json"
else
    echo -e "${RED}[ERROR]${NC} Failed to copy public key"
    exit 1
fi

echo ""
echo -e "${BLUE}[STEP 2.5]${NC} Fetching Ed25519 signature verification key from auth-server..."
SIG_ENDPOINT_PRIMARY="http://auth-server:8080/api/v1/plugins/signature/public-key"
SIG_ENDPOINT_ALT1="http://nebeniac-auth:8080/api/v1/plugins/signature/public-key"
SIG_ENDPOINT_ALT2="http://localhost:8080/api/v1/plugins/signature/public-key"

SIG_PUBLIC_KEY=""
for TRY in $(seq 1 30); do
  RESP=$(curl -fsS "$SIG_ENDPOINT_PRIMARY" 2>/dev/null || curl -fsS "$SIG_ENDPOINT_ALT1" 2>/dev/null || curl -fsS "$SIG_ENDPOINT_ALT2" 2>/dev/null || true)
  if [ -n "$RESP" ]; then
    SIG_PUBLIC_KEY=$(echo "$RESP" | jq -r '.publicKey // empty' 2>/dev/null || true)
  fi
  if [ -n "$SIG_PUBLIC_KEY" ]; then
    break
  fi
  echo -e "${YELLOW}[WAIT]${NC} Waiting for signature key... (${TRY}/30)"
  sleep 1
done

if [ -z "$SIG_PUBLIC_KEY" ]; then
  echo -e "${RED}[ERROR]${NC} Could not fetch signature public key from auth-server"
  exit 1
fi

echo -e "${GREEN}[SUCCESS]${NC} Signature key fetched (len: ${#SIG_PUBLIC_KEY})"

CONFIG_YML="${RESOURCES_DIR}/config.yml"
if [ ! -f "$CONFIG_YML" ]; then
  printf "security:\n  signature-public-key: \"%s\"\n" "$SIG_PUBLIC_KEY" > "$CONFIG_YML"
else
  if grep -qE '^[[:space:]]*signature-public-key:' "$CONFIG_YML"; then
    sed -i -E 's|^([[:space:]]*signature-public-key:[[:space:]]*).*$|\1"'"$SIG_PUBLIC_KEY"'"|' "$CONFIG_YML"
  else
    if grep -qE '^security:[[:space:]]*$' "$CONFIG_YML"; then
      sed -i '/^security:[[:space:]]*$/a\  signature-public-key: '"\"$SIG_PUBLIC_KEY\"" "$CONFIG_YML"
    else
      printf "\nsecurity:\n  signature-public-key: \"%s\"\n" "$SIG_PUBLIC_KEY" >> "$CONFIG_YML"
    fi
  fi
fi

echo -e "${GREEN}[CONFIRMED]${NC} Injected signature key into ${CONFIG_YML}"

echo ""
echo -e "${BLUE}[STEP 3]${NC} Building plugin with Maven..."
cd "${PLUGIN_DIR}"

mvn clean package -DskipTests

if [ $? -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Maven build failed"
    exit 1
fi

echo -e "${GREEN}[SUCCESS]${NC} Maven build completed"

echo ""
echo -e "${BLUE}[STEP 4]${NC} Copying built JAR to output directory..."

JAR_FILE=$(find target -name "loader-*.jar" -not -name "*-sources.jar" -not -name "*-javadoc.jar" | head -1)

if [ -z "${JAR_FILE}" ]; then
    echo -e "${RED}[ERROR]${NC} No JAR file found in target directory"
    exit 1
fi

echo -e "${BLUE}[INFO]${NC} Found JAR: ${JAR_FILE}"

mkdir -p "${OUTPUT_DIR}"

cp "${JAR_FILE}" "${OUTPUT_DIR}/loader.jar"

if [ -f "${OUTPUT_DIR}/loader.jar" ]; then
    JAR_SIZE=$(stat -c%s "${OUTPUT_DIR}/loader.jar")
    echo -e "${GREEN}[SUCCESS]${NC} Plugin JAR copied to: ${OUTPUT_DIR}/loader.jar"
    echo -e "${BLUE}[INFO]${NC} JAR size: ${JAR_SIZE} bytes"

    echo ""
    echo -e "${BLUE}[VERIFY]${NC} Checking if public key is included in JAR..."
    if unzip -l "${OUTPUT_DIR}/loader.jar" | grep -q "server_public_key.json"; then
        echo -e "${GREEN}[CONFIRMED]${NC} server_public_key.json is included in the JAR"
    else
        echo -e "${YELLOW}[WARNING]${NC} server_public_key.json not found in JAR listing"
    fi
else
    echo -e "${RED}[ERROR]${NC} Failed to copy JAR to output directory"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Build Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${BLUE}[OUTPUT]${NC} loader.jar is ready at:"
echo -e "         ${OUTPUT_DIR}/loader.jar"
echo -e "${BLUE}[NEXT]${NC} Copy this JAR to your Spigot/Bukkit plugins folder"
echo ""

sleep 2

exit 0
