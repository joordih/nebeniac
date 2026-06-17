#!/bin/bash

set -e

KEYS_DIR="${E2EE_KEYS_PATH:-/app/keys}"
PUBLIC_KEY_FILE="${KEYS_DIR}/server_public_key.json"
PLUGIN_LOADER_DIR="${PLUGIN_LOADER_PATH:-../loader/src/main/resources}"
TARGET_KEY_FILE="${PLUGIN_LOADER_DIR}/server_public_key.json"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  E2EE Key Sync to Plugin Loader${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

MAX_WAIT=30
WAIT_COUNT=0

while [ ! -f "${PUBLIC_KEY_FILE}" ] && [ ${WAIT_COUNT} -lt ${MAX_WAIT} ]; do
    echo -e "${YELLOW}[WAIT]${NC} Waiting for public key to be generated... (${WAIT_COUNT}/${MAX_WAIT})"
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))
done

if [ ! -f "${PUBLIC_KEY_FILE}" ]; then
    echo -e "${RED}[ERROR]${NC} Public key not found after ${MAX_WAIT} seconds"
    echo -e "${YELLOW}[INFO]${NC} Public key will be synced when available"
    exit 0
fi

echo -e "${GREEN}[FOUND]${NC} Public key located at: ${PUBLIC_KEY_FILE}"

mkdir -p "${PLUGIN_LOADER_DIR}" 2>/dev/null || true

echo -e "${BLUE}[SYNC]${NC} Copying public key to plugin loader..."
cp "${PUBLIC_KEY_FILE}" "${TARGET_KEY_FILE}"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}[SUCCESS]${NC} Public key synced to: ${TARGET_KEY_FILE}"

    if command -v jq &> /dev/null; then
        KEY_TYPE=$(jq -r '.primaryKeyId' "${TARGET_KEY_FILE}" 2>/dev/null || echo "unknown")
        echo -e "${BLUE}[INFO]${NC} Key ID: ${KEY_TYPE}"
    fi

    KEY_SIZE=$(stat -f%z "${TARGET_KEY_FILE}" 2>/dev/null || stat -c%s "${TARGET_KEY_FILE}" 2>/dev/null || echo "unknown")
    echo -e "${BLUE}[INFO]${NC} Key size: ${KEY_SIZE} bytes"
else
    echo -e "${RED}[ERROR]${NC} Failed to copy public key"
    exit 1
fi

if [ "${WATCH_MODE:-false}" = "true" ]; then
    echo ""
    echo -e "${BLUE}[WATCH]${NC} Monitoring for key changes..."

    if command -v inotifywait &> /dev/null; then
        inotifywait -m -e modify,create "${PUBLIC_KEY_FILE}" |
        while read path action file; do
            echo -e "${YELLOW}[CHANGE]${NC} Public key changed, re-syncing..."
            cp "${PUBLIC_KEY_FILE}" "${TARGET_KEY_FILE}"
            echo -e "${GREEN}[SYNCED]${NC} Key updated at $(date '+%Y-%m-%d %H:%M:%S')"
        done
    else
        echo -e "${YELLOW}[WARN]${NC} inotifywait not available, watch mode disabled"
    fi
fi

echo ""
echo -e "${GREEN}E2EE key sync complete${NC}"
echo ""

exit 0
