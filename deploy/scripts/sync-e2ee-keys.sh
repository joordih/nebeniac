#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
AUTH_DIR="$PROJECT_ROOT/auth"
LOADER_DIR="$PROJECT_ROOT/loader"
DOCKER_DIR="$PROJECT_ROOT/deploy/docker"

AUTH_CONTAINER="nebeniac-auth"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  E2EE Key Synchronization Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

show_help() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help"
    echo "  -s, --skip-build        Skip recompiling loader"
    echo "  -m, --minecraft PATH    Copy the JAR to the Minecraft server at PATH"
    echo "  -f, --force             Force key regeneration on the server"
    echo ""
    echo "Example:"
    echo "  $0                                    # Sync and recompile"
    echo "  $0 -m /opt/minecraft/plugins          # Sync, recompile, and copy"
    echo "  $0 -f                                 # Regenerate keys and sync"
    exit 0
}

SKIP_BUILD=false
MINECRAFT_PATH=""
FORCE_REGENERATE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            ;;
        -s|--skip-build)
            SKIP_BUILD=true
            shift
            ;;
        -m|--minecraft)
            MINECRAFT_PATH="$2"
            shift 2
            ;;
        -f|--force)
            FORCE_REGENERATE=true
            shift
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            show_help
            ;;
    esac
done

if ! docker info > /dev/null 2>&1; then
    echo -e "${YELLOW}Docker is not running. Skipping key synchronization.${NC}"
    exit 0
fi

echo -e "${GREEN}✓${NC} Docker is running"

if ! docker ps -a --format '{{.Names}}' | grep -q "^${AUTH_CONTAINER}$"; then
    echo -e "${YELLOW}Container ${AUTH_CONTAINER} not found${NC}"
    echo -e "${BLUE}→ Building and starting container...${NC}"
    cd "$DOCKER_DIR"
    docker-compose up -d auth-server
    echo -e "${GREEN}✓${NC} Container started"
    sleep 5
fi

if ! docker ps --format '{{.Names}}' | grep -q "^${AUTH_CONTAINER}$"; then
    echo -e "${YELLOW}Container ${AUTH_CONTAINER} is not running${NC}"
    echo -e "${BLUE}→ Starting container...${NC}"
    cd "$DOCKER_DIR"
    docker-compose start auth-server
    echo -e "${GREEN}✓${NC} Container started"
    sleep 5
fi

if [ "$FORCE_REGENERATE" = true ]; then
    echo -e "${BLUE}→ Regenerating E2EE keys on server...${NC}"
    docker exec "$AUTH_CONTAINER" rm -rf /app/keys/
    docker-compose -f "$DOCKER_DIR/docker-compose.yml" restart auth-server
    sleep 5
    echo -e "${GREEN}✓${NC} Keys regenerated"
fi

echo -e "${BLUE}→ Verifying keys on auth server...${NC}"
if ! docker exec "$AUTH_CONTAINER" test -f /app/keys/server_public_key.json; then
    echo -e "${RED}✗ Error: Public key does not exist on server${NC}"
    echo -e "${YELLOW}  Waiting 10 s for key generation...${NC}"
    sleep 10
    if ! docker exec "$AUTH_CONTAINER" test -f /app/keys/server_public_key.json; then
        echo -e "${RED}✗ Error: Keys were not generated. Check server logs.${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}✓${NC} Keys found on server"

TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

echo -e "${BLUE}→ Extracting public key from server...${NC}"
docker cp "${AUTH_CONTAINER}:/app/keys/server_public_key.json" "$TMP_DIR/server_public_key.json"

if [ ! -f "$TMP_DIR/server_public_key.json" ]; then
    echo -e "${RED}✗ Error: Could not copy public key${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Public key extracted"

KEY_SIZE=$(wc -c < "$TMP_DIR/server_public_key.json")
if [ "$KEY_SIZE" -lt 100 ]; then
    echo -e "${RED}✗ Error: Public key appears corrupt (size: $KEY_SIZE bytes)${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Public key valid (size: $KEY_SIZE bytes)"

echo -e "${BLUE}→ Copying key to loader...${NC}"
LOADER_RESOURCES="$LOADER_DIR/src/main/resources"

if [ ! -d "$LOADER_RESOURCES" ]; then
    echo -e "${RED}✗ Error: Resources directory not found: $LOADER_RESOURCES${NC}"
    exit 1
fi

cp "$TMP_DIR/server_public_key.json" "$LOADER_RESOURCES/server_public_key.json"
echo -e "${GREEN}✓${NC} Key copied to: $LOADER_RESOURCES/server_public_key.json"

echo ""
echo -e "${BLUE}Key information:${NC}"
echo "-----------------------------------"
cat "$TMP_DIR/server_public_key.json" | head -c 200
echo "..."
echo "-----------------------------------"
echo ""

if [ "$SKIP_BUILD" = false ]; then
    echo -e "${BLUE}→ Recompiling loader...${NC}"
    cd "$LOADER_DIR"

    if ! mvn clean package -DskipTests > /dev/null 2>&1; then
        echo -e "${RED}✗ Error compiling loader${NC}"
        echo -e "${YELLOW}  Run manually: cd $LOADER_DIR && mvn clean package${NC}"
        exit 1
    fi

    echo -e "${GREEN}✓${NC} Loader compiled successfully"

    LOADER_JAR="$LOADER_DIR/target/loader-1.0-SNAPSHOT.jar"
    if [ ! -f "$LOADER_JAR" ]; then
        echo -e "${RED}✗ Error: JAR not found: $LOADER_JAR${NC}"
        exit 1
    fi

    JAR_SIZE=$(du -h "$LOADER_JAR" | cut -f1)
    echo -e "${GREEN}✓${NC} JAR generated: $LOADER_JAR ($JAR_SIZE)"
else
    echo -e "${YELLOW}Compilation skipped (--skip-build)${NC}"
    LOADER_JAR="$LOADER_DIR/target/loader-1.0-SNAPSHOT.jar"
fi

if [ -n "$MINECRAFT_PATH" ]; then
    echo -e "${BLUE}→ Copying JAR to Minecraft server...${NC}"

    if [ ! -d "$MINECRAFT_PATH" ]; then
        echo -e "${RED}✗ Error: Directory not found: $MINECRAFT_PATH${NC}"
        exit 1
    fi

    if [ ! -f "$LOADER_JAR" ]; then
        echo -e "${RED}✗ Error: JAR not found: $LOADER_JAR${NC}"
        echo -e "${YELLOW}  Run without --skip-build first${NC}"
        exit 1
    fi

    cp "$LOADER_JAR" "$MINECRAFT_PATH/loader-1.0-SNAPSHOT.jar"
    echo -e "${GREEN}✓${NC} JAR copied to: $MINECRAFT_PATH"

    if ls "$MINECRAFT_PATH"/loader*.jar 2>/dev/null | grep -v "loader-1.0-SNAPSHOT.jar" > /dev/null; then
        echo -e "${YELLOW}Found old loader JARs${NC}"
        echo -e "${BLUE}→ Remove them? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            find "$MINECRAFT_PATH" -name "loader*.jar" ! -name "loader-1.0-SNAPSHOT.jar" -delete
            echo -e "${GREEN}✓${NC} Old JARs removed"
        fi
    fi
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  ✓ Sync complete${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Summary:${NC}"
echo -e "  • Public key synchronized"
if [ "$SKIP_BUILD" = false ]; then
    echo -e "  • Loader recompiled"
fi
if [ -n "$MINECRAFT_PATH" ]; then
    echo -e "  • JAR copied to Minecraft server"
fi
echo ""
echo -e "${YELLOW}Next steps:${NC}"
if [ -z "$MINECRAFT_PATH" ]; then
    echo -e "  1. Copy the JAR to the Minecraft server:"
    echo -e "     ${BLUE}cp $LOADER_JAR /path/to/minecraft/plugins/${NC}"
fi
echo -e "  2. Restart the Minecraft server"
echo -e "  3. E2EE keys are now synchronized"
echo ""
