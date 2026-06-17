#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DOCKER_DIR="${REPO_ROOT}/deploy/docker"
SCRIPTS_DIR="${REPO_ROOT}/deploy/scripts"

MAVEN_MODULES="auth,loader,protector"
DASHBOARD_DIR="${REPO_ROOT}/dashboard"

DRY_RUN=false
SKIP_BUILD=false
SKIP_SYNC=false
SKIP_UP=false
NO_CACHE=false
COMPOSE_PROFILE=""
EXTRA_COMPOSE_FILES=()

usage() {
  cat <<'EOF'
Usage: ./docker_deploy.sh [options]

Options:
  --skip-build         Skip Maven/NPM builds
  --skip-sync          Skip E2EE key synchronization
  --skip-up            Build Docker images only (no docker compose up)
  --no-cache           Build Docker images without cache
  --profile NAME       Use deploy/docker/docker-compose.NAME.yml in addition to default
  --dry-run            Print commands without executing
  -h, --help           Show this message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) SKIP_BUILD=true ;;
    --skip-sync)  SKIP_SYNC=true ;;
    --skip-up)    SKIP_UP=true ;;
    --no-cache)   NO_CACHE=true ;;
    --profile)
      shift
      [[ $# -gt 0 ]] || { echo "Missing profile name after --profile" >&2; exit 1; }
      COMPOSE_PROFILE="$1"
      EXTRA_COMPOSE_FILES+=("-f" "${DOCKER_DIR}/docker-compose.${COMPOSE_PROFILE}.yml")
      ;;
    --dry-run)    DRY_RUN=true ;;
    -h|--help)    usage; exit 0 ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

log() {
  local level="$1"; shift
  printf '[%s] %s\n' "$level" "$*"
}

run() {
  if [[ "$DRY_RUN" == true ]]; then
    log "DRY-RUN" "$*"
  else
    log "EXEC" "$*"
    eval "$@"
    local status=$?
    if (( status != 0 )); then
      log "ERROR" "Command failed with exit code $status"
      exit "$status"
    fi
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    log "ERROR" "Missing required command: $cmd"
    exit 1
  fi
}

detect_compose_cmd() {
  if command -v docker-compose >/dev/null 2>&1; then
    echo "docker-compose"
  else
    echo "docker compose"
  fi
}

COMPOSE_CMD="$(detect_compose_cmd)"

require_cmd docker
require_cmd "$COMPOSE_CMD"
require_cmd mvn
require_cmd npm

if ! docker info >/dev/null 2>&1; then
  log "ERROR" "Docker engine is not running. Please start Docker and retry."
  exit 1
fi

[[ -d "$DOCKER_DIR" ]] || { log "ERROR" "Docker directory not found at $DOCKER_DIR"; exit 1; }

if [[ "$SKIP_BUILD" == true ]]; then
  log "INFO" "Skipping build phase (--skip-build)"
else
  log "INFO" "Building Java modules: $MAVEN_MODULES"
  run "cd \"$REPO_ROOT\" && mvn -pl \"$MAVEN_MODULES\" -am clean package -DskipTests"

  if [[ -d "$DASHBOARD_DIR" ]]; then
    log "INFO" "Building dashboard assets"
    run "cd \"$DASHBOARD_DIR\" && pnpm install"
    run "cd \"$DASHBOARD_DIR\" && pnpm run build"
  else
    log "WARN" "Dashboard directory not found at $DASHBOARD_DIR (skipping frontend build)"
  fi
fi

SYNC_SCRIPT="${SCRIPTS_DIR}/sync-e2ee-keys.sh"
if [[ "$SKIP_SYNC" == true ]]; then
  log "INFO" "Skipping E2EE key synchronization (--skip-sync)"
elif [[ -x "$SYNC_SCRIPT" ]]; then
  log "INFO" "Running E2EE key synchronization"
  run "\"$SYNC_SCRIPT\" --skip-build"
else
  log "WARN" "E2EE sync script not found or not executable at $SYNC_SCRIPT"
fi

BUILD_FLAGS=()
if [[ "$NO_CACHE" == true ]]; then
  BUILD_FLAGS+=(--no-cache)
fi

COMPOSE_FILES=(-f "${DOCKER_DIR}/docker-compose.yml")
if [[ ${#EXTRA_COMPOSE_FILES[@]} -gt 0 ]]; then
  COMPOSE_FILES+=("${EXTRA_COMPOSE_FILES[@]}")
fi

log "INFO" "Building Docker images"
run "cd \"$DOCKER_DIR\" && $COMPOSE_CMD ${COMPOSE_FILES[*]} build ${BUILD_FLAGS[*]}"

if [[ "$SKIP_UP" == true ]]; then
  log "INFO" "Skipping docker compose up (--skip-up)"
else
  log "INFO" "Launching stack with docker compose up -d"
  run "cd \"$DOCKER_DIR\" && $COMPOSE_CMD ${COMPOSE_FILES[*]} up -d"
  log "INFO" "Deployment complete. Use '$COMPOSE_CMD -f deploy/docker/docker-compose.yml logs -f' to follow logs."
fi
