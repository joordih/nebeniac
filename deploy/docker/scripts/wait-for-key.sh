#!/bin/bash

##############################################################################
# Wait for E2EE Public Key Script
#
# This script waits for the auth-server to generate the E2EE public key
# before proceeding with the plugin build
##############################################################################

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

# Configuration
KEYS_DIR="/app/keys"
PUBLIC_KEY_FILE="${KEYS_DIR}/server_public_key.json"
MAX_WAIT=120  # Maximum wait time in seconds
CHECK_INTERVAL=2  # Check every 2 seconds

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Waiting for E2EE Public Key${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

echo -e "${BLUE}[INFO]${NC} Waiting for auth-server to generate E2EE keys..."
echo -e "${BLUE}[INFO]${NC} Looking for: ${PUBLIC_KEY_FILE}"

WAIT_COUNT=0
DOTS=""

while [ ! -f "${PUBLIC_KEY_FILE}" ]; do
    if [ ${WAIT_COUNT} -ge ${MAX_WAIT} ]; then
        echo ""
        echo -e "${RED}[ERROR]${NC} Timeout waiting for public key after ${MAX_WAIT} seconds"
        echo -e "${YELLOW}[INFO]${NC} Make sure auth-server is running and healthy"
        exit 1
    fi
    
    # Print progress every 10 seconds
    if [ $((WAIT_COUNT % 10)) -eq 0 ] && [ ${WAIT_COUNT} -gt 0 ]; then
        echo -e "${YELLOW}[WAIT]${NC} Still waiting... (${WAIT_COUNT}/${MAX_WAIT}s)"
    fi
    
    sleep ${CHECK_INTERVAL}
    WAIT_COUNT=$((WAIT_COUNT + CHECK_INTERVAL))
done

echo ""
echo -e "${GREEN}[SUCCESS]${NC} Public key found!"

# Validate the key file
if [ -s "${PUBLIC_KEY_FILE}" ]; then
    KEY_SIZE=$(stat -c%s "${PUBLIC_KEY_FILE}")
    echo -e "${BLUE}[INFO]${NC} Public key size: ${KEY_SIZE} bytes"
    
    # Try to validate JSON structure
    if command -v jq &> /dev/null; then
        if jq empty "${PUBLIC_KEY_FILE}" 2>/dev/null; then
            echo -e "${GREEN}[VALID]${NC} Public key is valid JSON"
        else
            echo -e "${RED}[ERROR]${NC} Public key is not valid JSON!"
            exit 1
        fi
    fi
else
    echo -e "${RED}[ERROR]${NC} Public key file is empty!"
    exit 1
fi

echo ""
echo -e "${GREEN}✓ Ready to proceed with plugin build${NC}"
echo ""

exit 0
