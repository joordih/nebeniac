# Nebeniac

A self-hosted licensing and plugin protection platform for Minecraft (Bukkit/Spigot/Paper) plugins.

Nebeniac lets you distribute encrypted Minecraft plugins that only run on servers holding a valid license issued by your auth server. It combines bytecode encryption, end-to-end encrypted API communication, Ed25519 JAR signing, and a web dashboard for license management.

## Components

| Directory | Role |
|-----------|------|
| `auth/` | Spring/Spark Java HTTP server — manages licenses, plugins, activations, and E2EE key material |
| `protector/` | Standalone Java tool — takes a plain plugin JAR and produces an AES-encrypted JAR with obfuscated bytecode |
| `loader/` | Bukkit/Spigot plugin — runs on the Minecraft server, contacts the auth server to validate a license, decrypts the protected JAR at runtime, and loads it |
| `dashboard/` | React + Vite frontend for managing licenses, plugins, and activations |
| `deploy/docker/` | Docker Compose stack (auth, dashboard, MongoDB, RabbitMQ, nginx, protector, plugin-builder) |
| `deploy/scripts/` | Helper scripts for key generation, E2EE sync, JAR signing, and full deployment |

## How it works

1. You run the auth server and dashboard on your own infrastructure.
2. You protect a plugin JAR with the protector tool; this encrypts the class bytecode and embeds the server's public E2EE key.
3. You create a license in the dashboard and distribute the encrypted JAR to your customer.
4. The customer installs the loader on their Minecraft server. At startup the loader contacts your auth server, validates the license, receives the AES decryption key over E2EE, and loads the plugin in memory — the plain bytecode never touches disk.
5. An Ed25519 signature on the JAR prevents tampered builds from loading.

## Requirements

- Java 17+, Maven 3.8+
- Node.js 18+, pnpm
- Docker and Docker Compose (for the full stack)
- OpenSSL (for key generation)

## Quick start

### 1. Generate Ed25519 signing keys

```bash
bash deploy/scripts/generate-signature-keys.sh
```

Keys are written to `auth/keys/signatures/`. The private key stays on your server; never commit it.

### 2. Configure environment

Copy the example env file and fill in your values:

```bash
cp deploy/docker/.env.example deploy/docker/.env
```

Required variables:

```
RABBITMQ_PASSWORD=
MONGO_ROOT_PASSWORD=
MONGODB_URI=mongodb://nebeniac:<password>@mongodb:27017/nebeniac?authSource=admin
GOOGLE_OAUTH_CLIENT_ID=
GOOGLE_OAUTH_CLIENT_SECRET=
GOOGLE_OAUTH_REFRESH_TOKEN=
EMAIL_FROM=
```

Optional secrets (if unset, the auth server generates them once and stores them with owner-only
permissions in `/app/data/secrets` on the `auth_data` volume; never commit or log them):

```
JWT_SECRET=            # at least 32 characters
NEBENIAC_MASTER_KEK=   # Base64 of 32 random bytes, e.g. `openssl rand -base64 32`
NEBENIAC_SETUP_TOKEN=  # one-time token required to create the first administrator
```

On first start with no users, the auth server requires a setup token to create the first administrator.
Set `NEBENIAC_SETUP_TOKEN`, or read the generated one with
`docker exec nebeniac-auth cat /app/data/secrets/setup_token`, and paste it into the setup page.

### 3. Start the stack

```bash
make docker-build
make docker-up
```

Or use the deploy script directly:

```bash
bash deploy/scripts/docker_deploy.sh
```

Dashboard is available at `http://localhost:3000`. Auth API at `http://localhost:8080/api/v1`.

### 4. Protect a plugin

Place a plain plugin JAR in the protector input volume and the stack processes it automatically, or run the protector directly:

```bash
java -jar protector/target/protector-1.0-SNAPSHOT.jar \
  input.jar output-encrypted.jar <license-key> <plugin-id>
```

### 5. Build the loader for distribution

The `plugin-builder` Docker service builds `loader.jar` automatically when the stack starts. Find it in `dist/plugins/`. Drop it in the Minecraft server's `plugins/` folder alongside any encrypted JARs.

### 6. Sync E2EE keys after rotating

```bash
make sync-keys
```

Or with Minecraft server path:

```bash
make sync-keys-minecraft MINECRAFT_PATH=/opt/minecraft/plugins
```

## Build targets

```
make build-auth        # Build the auth server JAR
make build-loader      # Build the loader plugin JAR
make build-protector   # Build the protector tool JAR
make build-all         # Build all three

make docker-build      # Build all Docker images
make docker-up         # Start the full stack
make docker-down       # Stop the stack
make docker-logs       # Follow logs

make sync-keys         # Sync E2EE public key to the loader
make regenerate-keys   # Rotate E2EE keys and re-sync
make sign-jar          # Sign an encrypted JAR with Ed25519

make status            # Show running services and built artifacts
make check-keys        # Verify E2EE key synchronization state
```

## Security notes

- The private E2EE key and Ed25519 signing key are generated per deployment and never leave the auth server.
- All license validation traffic between the loader and the auth server is encrypted end-to-end using Google Tink ECIES.
- The auth server rate-limits E2EE endpoints and rotates key material on a configurable schedule.
- The Docker stack runs all application containers as non-root (UID 1001).
- The host Docker socket mount on the auth container is read-only and intended for orchestration only; remove it if you do not need plugin hot-reloading.

## Project structure

```
nebeniac/
  auth/                   Spring/Spark Java auth server
  protector/              Plugin encryption tool
  loader/                 Bukkit runtime loader plugin
  dashboard/              React management frontend
  deploy/
    docker/               Dockerfiles, Compose file, nginx config, mongo init
      scripts/            Container entrypoint and build scripts
    scripts/              Host-side deployment and key management scripts
  Makefile                Top-level build automation
  pom.xml                 Maven multi-module parent (auth, protector, loader)
```

## License

This project is provided as-is for self-hosting. See `LICENSE` if present.
