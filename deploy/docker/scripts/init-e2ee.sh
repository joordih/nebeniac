#!/bin/bash

##############################################################################
# E2EE Initialization Script for Docker
#
# This script initializes the E2EE (End-to-End Encryption) system in Docker.
# It ensures proper setup of encryption keys, directories, and permissions.
#
# Usage: Called automatically by Docker entrypoint
##############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
KEYS_DIR="${E2EE_KEYS_PATH:-/app/keys}"
PRIVATE_KEY_FILE="${KEYS_DIR}/server_private_key.json"
PUBLIC_KEY_FILE="${KEYS_DIR}/server_public_key.json"
ARCHIVE_DIR="${KEYS_DIR}/archive"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  E2EE Initialization for Docker${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if E2EE is enabled
if [ "${E2EE_ENABLED:-true}" != "true" ]; then
    print_warning "E2EE is disabled by configuration"
    echo "Set E2EE_ENABLED=true to enable end-to-end encryption"
    exit 0
fi

print_info "E2EE is enabled"
print_info "Keys directory: ${KEYS_DIR}"

# Create keys directory if it doesn't exist
if [ ! -d "${KEYS_DIR}" ]; then
    print_info "Creating keys directory: ${KEYS_DIR}"
    mkdir -p "${KEYS_DIR}"
    if [ $? -eq 0 ]; then
        print_success "Keys directory created"
    else
        print_error "Failed to create keys directory"
        exit 1
    fi
else
    print_info "Keys directory already exists"
fi

# Create archive directory for key rotation
if [ ! -d "${ARCHIVE_DIR}" ]; then
    print_info "Creating archive directory: ${ARCHIVE_DIR}"
    mkdir -p "${ARCHIVE_DIR}"
fi

# Check if keys already exist
if [ -f "${PRIVATE_KEY_FILE}" ] && [ -f "${PUBLIC_KEY_FILE}" ]; then
    print_success "E2EE keys found"

    # Validate keys are valid JSON
    if command -v jq &> /dev/null; then
        print_info "Validating key files..."

        if jq empty "${PRIVATE_KEY_FILE}" 2>/dev/null; then
            print_success "Private key is valid JSON"
        else
            print_error "Private key is not valid JSON!"
            print_warning "Keys will be regenerated on server start"
        fi

        if jq empty "${PUBLIC_KEY_FILE}" 2>/dev/null; then
            print_success "Public key is valid JSON"
        else
            print_error "Public key is not valid JSON!"
            print_warning "Keys will be regenerated on server start"
        fi
    else
        print_warning "jq not installed, skipping JSON validation"
    fi

    # Display key information
    PRIVATE_KEY_SIZE=$(stat -f%z "${PRIVATE_KEY_FILE}" 2>/dev/null || stat -c%s "${PRIVATE_KEY_FILE}" 2>/dev/null || echo "unknown")
    PUBLIC_KEY_SIZE=$(stat -f%z "${PUBLIC_KEY_FILE}" 2>/dev/null || stat -c%s "${PUBLIC_KEY_FILE}" 2>/dev/null || echo "unknown")

    print_info "Private key size: ${PRIVATE_KEY_SIZE} bytes"
    print_info "Public key size: ${PUBLIC_KEY_SIZE} bytes"

    # Check last modification time
    if command -v date &> /dev/null; then
        PRIVATE_KEY_DATE=$(date -r "${PRIVATE_KEY_FILE}" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown")
        print_info "Keys last modified: ${PRIVATE_KEY_DATE}"
    fi

else
    print_warning "E2EE keys not found"
    print_info "Keys will be generated automatically on first server start"
    print_info "This is normal for first-time setup"
fi

# Set proper permissions
print_info "Setting permissions on keys directory..."
chmod 700 "${KEYS_DIR}" 2>/dev/null || true

if [ -f "${PRIVATE_KEY_FILE}" ]; then
    chmod 600 "${PRIVATE_KEY_FILE}" 2>/dev/null || true
    print_success "Private key permissions set (600)"
fi

if [ -f "${PUBLIC_KEY_FILE}" ]; then
    chmod 644 "${PUBLIC_KEY_FILE}" 2>/dev/null || true
    print_success "Public key permissions set (644)"
fi

# Display E2EE configuration
echo ""
echo -e "${BLUE}E2EE Configuration:${NC}"
echo "  Keys Path:              ${KEYS_DIR}"
echo "  Response Encryption:    ${E2EE_RESPONSE_ENCRYPTION:-true}"
echo "  Key Rotation:           ${E2EE_KEY_ROTATION_ENABLED:-true}"
echo "  Rotation Period:        ${E2EE_KEY_ROTATION_DAYS:-30} days"
echo "  Rate Limiting:          ${E2EE_RATE_LIMIT_ENABLED:-true}"
echo "  Rate Limit:             ${E2EE_RATE_LIMIT_REQUESTS_PER_MINUTE:-60} req/min"

# Check for archived keys (from previous rotations)
if [ -d "${ARCHIVE_DIR}" ]; then
    ARCHIVED_COUNT=$(find "${ARCHIVE_DIR}" -name "server_private_key_*.json" 2>/dev/null | wc -l)
    if [ "${ARCHIVED_COUNT}" -gt 0 ]; then
        print_info "Found ${ARCHIVED_COUNT} archived key(s) from previous rotations"
    fi
fi

echo ""
print_success "E2EE initialization complete"

# Display next steps
echo ""
echo -e "${BLUE}Next Steps:${NC}"
echo "  1. Server will generate keys automatically if not present"
echo "  2. Public key will be available at: /api/v1/e2ee/public-key"
echo "  3. Clients should fetch and embed the public key"
echo "  4. Monitor key rotation at: /api/v1/e2ee/stats"

# Export public key location for other scripts
export E2EE_PUBLIC_KEY_FILE="${PUBLIC_KEY_FILE}"

echo ""
echo -e "${GREEN}✓ Ready to start auth server with E2EE support${NC}"
echo ""

exit 0
