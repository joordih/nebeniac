#!/bin/bash

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Nebeniac Auth Server Starting${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

if [ -f "/app/scripts/init-e2ee.sh" ]; then
    echo -e "${BLUE}[INIT]${NC} Running E2EE initialization..."
    bash /app/scripts/init-e2ee.sh
else
    echo -e "${YELLOW}[WARN]${NC} E2EE init script not found, skipping..."
fi

echo -e "${BLUE}[START]${NC} Starting auth server..."
java -jar /app/auth.jar &
AUTH_PID=$!

echo -e "${GREEN}[INFO]${NC} Auth server started with PID: ${AUTH_PID}"

echo -e "${BLUE}[WAIT]${NC} Waiting for E2EE keys to be generated..."

KEYS_DIR="${E2EE_KEYS_PATH:-/app/keys}"
PUBLIC_KEY_FILE="${KEYS_DIR}/server_public_key.json"
SHARED_PLUGIN_RESOURCES="/app/plugins/loader-resources"

MAX_WAIT=60
WAIT_COUNT=0

while [ ! -f "${PUBLIC_KEY_FILE}" ] && [ ${WAIT_COUNT} -lt ${MAX_WAIT} ]; do
    if [ $((WAIT_COUNT % 5)) -eq 0 ]; then
        echo -e "${YELLOW}[WAIT]${NC} Still waiting for public key... (${WAIT_COUNT}/${MAX_WAIT}s)"
    fi
    sleep 1
    WAIT_COUNT=$((WAIT_COUNT + 1))

    if ! kill -0 ${AUTH_PID} 2>/dev/null; then
        echo -e "${RED}[ERROR]${NC} Auth server died during startup!"
        exit 1
    fi
done

if [ -f "${PUBLIC_KEY_FILE}" ]; then
    echo -e "${GREEN}[FOUND]${NC} E2EE public key generated successfully"

    mkdir -p "${SHARED_PLUGIN_RESOURCES}"

    echo -e "${BLUE}[SYNC]${NC} Copying public key to shared volume..."
    cp "${PUBLIC_KEY_FILE}" "${SHARED_PLUGIN_RESOURCES}/server_public_key.json"

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Public key synced to shared volume"
        echo -e "${BLUE}[INFO]${NC} Plugin loader can now access the key at:"
        echo -e "${BLUE}[INFO]${NC}   ${SHARED_PLUGIN_RESOURCES}/server_public_key.json"

        cp "${PUBLIC_KEY_FILE}" "/app/plugins/server_public_key.json" 2>/dev/null || true

        chmod 644 "${SHARED_PLUGIN_RESOURCES}/server_public_key.json"

        KEY_SIZE=$(stat -c%s "${PUBLIC_KEY_FILE}" 2>/dev/null || echo "unknown")
        echo -e "${BLUE}[INFO]${NC} Public key size: ${KEY_SIZE} bytes"
    else
        echo -e "${RED}[ERROR]${NC} Failed to sync public key to shared volume"
    fi

    if command -v inotifywait &> /dev/null; then
        (
            echo -e "${BLUE}[WATCH]${NC} Monitoring for key rotation..."
            inotifywait -m -e modify,create "${PUBLIC_KEY_FILE}" 2>/dev/null |
            while read path action file; do
                echo -e "${YELLOW}[UPDATE]${NC} Public key changed, re-syncing..."
                cp "${PUBLIC_KEY_FILE}" "${SHARED_PLUGIN_RESOURCES}/server_public_key.json"
                cp "${PUBLIC_KEY_FILE}" "/app/plugins/server_public_key.json" 2>/dev/null || true
                echo -e "${GREEN}[SYNCED]${NC} Updated at $(date '+%Y-%m-%d %H:%M:%S')"
            done
        ) &
    fi
else
    echo -e "${YELLOW}[WARN]${NC} Public key not generated within ${MAX_WAIT} seconds"
    echo -e "${YELLOW}[INFO]${NC} Server may still be initializing, key will be synced when available"
fi

echo ""
echo -e "${GREEN}Auth server initialization complete${NC}"
echo -e "${BLUE}[INFO]${NC} Server logs will follow..."
echo ""

wait ${AUTH_PID}
EXIT_CODE=$?

echo ""
echo -e "${YELLOW}[EXIT]${NC} Auth server stopped with code: ${EXIT_CODE}"

exit ${EXIT_CODE}
