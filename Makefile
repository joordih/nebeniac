.PHONY: help build build-all build-auth build-loader build-protector \
        docker-build docker-up docker-down docker-restart docker-logs \
        sync-keys clean clean-all install test \
        dev-auth dev-loader minecraft-install

BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
RED := \033[0;31m
NC := \033[0m

PROJECT_ROOT := $(shell pwd)
AUTH_DIR := $(PROJECT_ROOT)/auth
LOADER_DIR := $(PROJECT_ROOT)/loader
PROTECTOR_DIR := $(PROJECT_ROOT)/protector
DOCKER_DIR := $(PROJECT_ROOT)/deploy/docker
SCRIPTS_DIR := $(PROJECT_ROOT)/deploy/scripts

AUTH_JAR := $(AUTH_DIR)/target/auth-server.jar
LOADER_JAR := $(LOADER_DIR)/target/loader-1.0-SNAPSHOT.jar
PROTECTOR_JAR := $(PROTECTOR_DIR)/target/protector-1.0-SNAPSHOT.jar

MINECRAFT_PATH ?= ~/minecraft/plugins

.DEFAULT_GOAL := help

##@ General

help: ## Display this help message
	@echo "$(BLUE)========================================$(NC)"
	@echo "$(BLUE)  Nebeniac Project - Build System$(NC)"
	@echo "$(BLUE)========================================$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(CYAN)<target>$(NC)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(CYAN)%-20s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(YELLOW)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
	@echo ""

##@ Building

build-auth: ## Build auth server
	@echo "$(BLUE)→ Building auth server...$(NC)"
	@cd $(AUTH_DIR) && mvn clean package -DskipTests
	@echo "$(GREEN)✓ Auth server built: $(AUTH_JAR)$(NC)"

build-loader: ## Build loader
	@echo "$(BLUE)→ Building loader...$(NC)"
	@cd $(LOADER_DIR) && mvn clean package -DskipTests
	@echo "$(GREEN)✓ Loader built: $(LOADER_JAR)$(NC)"

build-protector: ## Build protector
	@echo "$(BLUE)→ Building protector...$(NC)"
	@cd $(PROTECTOR_DIR) && mvn clean package -DskipTests
	@echo "$(GREEN)✓ Protector built: $(PROTECTOR_JAR)$(NC)"

build-all: build-auth build-loader build-protector ## Build all components
	@echo "$(GREEN)✓ All components built successfully$(NC)"

build: build-auth build-loader ## Build auth and loader (most common)

##@ Docker

docker-build: ## Build Docker images
	@echo "$(BLUE)→ Building Docker images...$(NC)"
	@cd $(DOCKER_DIR) && docker-compose build
	@echo "$(GREEN)✓ Docker images built$(NC)"

docker-build-auth: ## Build only auth Docker image
	@echo "$(BLUE)→ Building auth Docker image...$(NC)"
	@cd $(DOCKER_DIR) && docker-compose build auth-server
	@echo "$(GREEN)✓ Auth Docker image built$(NC)"

docker-up: ## Start all Docker services
	@echo "$(BLUE)→ Starting Docker services...$(NC)"
	@cd $(DOCKER_DIR) && docker-compose up -d
	@echo "$(GREEN)✓ Docker services started$(NC)"
	@echo "$(YELLOW)Run 'make docker-logs' to view logs$(NC)"

docker-down: ## Stop all Docker services
	@echo "$(BLUE)→ Stopping Docker services...$(NC)"
	@cd $(DOCKER_DIR) && docker-compose down
	@echo "$(GREEN)✓ Docker services stopped$(NC)"

docker-restart: ## Restart all Docker services
	@echo "$(BLUE)→ Restarting Docker services...$(NC)"
	@cd $(DOCKER_DIR) && docker-compose restart
	@echo "$(GREEN)✓ Docker services restarted$(NC)"

docker-restart-auth: ## Restart only auth service
	@echo "$(BLUE)→ Restarting auth service...$(NC)"
	@cd $(DOCKER_DIR) && docker-compose restart auth-server
	@echo "$(GREEN)✓ Auth service restarted$(NC)"

docker-logs: ## Follow Docker logs
	@cd $(DOCKER_DIR) && docker-compose logs -f

docker-logs-auth: ## Follow auth server logs
	@cd $(DOCKER_DIR) && docker-compose logs -f auth-server

##@ E2EE Key Management

sync-keys: ## Sync E2EE keys from auth server to loader
	@echo "$(BLUE)→ Synchronizing E2EE keys...$(NC)"
	@bash $(SCRIPTS_DIR)/sync-e2ee-keys.sh
	@echo "$(GREEN)✓ Keys synchronized$(NC)"

sync-keys-skip-build: ## Sync keys without rebuilding loader
	@echo "$(BLUE)→ Synchronizing E2EE keys (skip build)...$(NC)"
	@bash $(SCRIPTS_DIR)/sync-e2ee-keys.sh --skip-build
	@echo "$(GREEN)✓ Keys synchronized$(NC)"

sync-keys-minecraft: ## Sync keys and copy to Minecraft server
	@echo "$(BLUE)→ Synchronizing E2EE keys and deploying to Minecraft...$(NC)"
	@bash $(SCRIPTS_DIR)/sync-e2ee-keys.sh --minecraft $(MINECRAFT_PATH)
	@echo "$(GREEN)✓ Keys synchronized and deployed$(NC)"

regenerate-keys: ## Regenerate E2EE keys on server
	@echo "$(BLUE)→ Regenerating E2EE keys...$(NC)"
	@bash $(SCRIPTS_DIR)/sync-e2ee-keys.sh --force
	@echo "$(GREEN)✓ Keys regenerated and synchronized$(NC)"

##@ Deployment

deploy-full: build-all docker-build docker-up sync-keys ## Full deployment: build, dockerize, start, sync keys
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)  ✓ Full deployment completed$(NC)"
	@echo "$(GREEN)========================================$(NC)"

deploy-auth: build-auth docker-build-auth docker-restart-auth sync-keys ## Deploy only auth changes
	@echo "$(GREEN)✓ Auth deployment completed$(NC)"

deploy-loader: build-loader sync-keys-skip-build ## Deploy only loader changes
	@echo "$(GREEN)✓ Loader deployment completed$(NC)"
	@echo "$(YELLOW)Remember to copy $(LOADER_JAR) to your Minecraft server$(NC)"

minecraft-install: build-loader ## Build and copy loader to Minecraft server
	@echo "$(BLUE)→ Installing to Minecraft server at $(MINECRAFT_PATH)...$(NC)"
	@if [ ! -d "$(MINECRAFT_PATH)" ]; then \
		echo "$(RED)✗ Error: Minecraft plugins directory not found: $(MINECRAFT_PATH)$(NC)"; \
		echo "$(YELLOW)Set MINECRAFT_PATH variable: make minecraft-install MINECRAFT_PATH=/your/path$(NC)"; \
		exit 1; \
	fi
	@cp $(LOADER_JAR) $(MINECRAFT_PATH)/
	@echo "$(GREEN)✓ Loader installed to $(MINECRAFT_PATH)$(NC)"
	@echo "$(YELLOW)Restart your Minecraft server to load the changes$(NC)"

##@ Development

dev-auth: ## Run auth server locally (without Docker)
	@echo "$(BLUE)→ Starting auth server locally...$(NC)"
	@cd $(AUTH_DIR) && java -jar target/auth-server.jar

dev-loader: ## Open loader project for development
	@echo "$(BLUE)→ Opening loader in IDE...$(NC)"
	@cd $(LOADER_DIR) && code . || idea . || echo "$(YELLOW)Open $(LOADER_DIR) in your IDE$(NC)"

install: ## Install dependencies for all projects
	@echo "$(BLUE)→ Installing dependencies...$(NC)"
	@cd $(AUTH_DIR) && mvn install -DskipTests
	@cd $(LOADER_DIR) && mvn install -DskipTests
	@cd $(PROTECTOR_DIR) && mvn install -DskipTests
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

test: ## Run tests for all projects
	@echo "$(BLUE)→ Running tests...$(NC)"
	@cd $(AUTH_DIR) && mvn test
	@cd $(LOADER_DIR) && mvn test
	@cd $(PROTECTOR_DIR) && mvn test
	@echo "$(GREEN)✓ Tests completed$(NC)"

##@ Cleaning

clean: ## Clean build artifacts
	@echo "$(BLUE)→ Cleaning build artifacts...$(NC)"
	@cd $(AUTH_DIR) && mvn clean
	@cd $(LOADER_DIR) && mvn clean
	@cd $(PROTECTOR_DIR) && mvn clean
	@echo "$(GREEN)✓ Build artifacts cleaned$(NC)"

clean-docker: ## Remove Docker containers and images
	@echo "$(BLUE)→ Cleaning Docker resources...$(NC)"
	@cd $(DOCKER_DIR) && docker-compose down -v --rmi local
	@echo "$(GREEN)✓ Docker resources cleaned$(NC)"

clean-all: clean clean-docker ## Clean everything including Docker
	@echo "$(GREEN)✓ Everything cleaned$(NC)"

##@ Quick Commands

quick-sync: ## Quick: sync keys and deploy to Minecraft
	@$(MAKE) sync-keys-minecraft MINECRAFT_PATH=$(MINECRAFT_PATH)

quick-deploy: ## Quick: build auth, deploy, and sync keys
	@$(MAKE) build-auth
	@$(MAKE) docker-build-auth
	@$(MAKE) docker-restart-auth
	@sleep 5
	@$(MAKE) sync-keys
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)  ✓ Quick deployment completed$(NC)"
	@echo "$(GREEN)========================================$(NC)"

##@ Information

status: ## Show status of all services
	@echo "$(BLUE)========================================$(NC)"
	@echo "$(BLUE)  Project Status$(NC)"
	@echo "$(BLUE)========================================$(NC)"
	@echo ""
	@echo "$(YELLOW)Docker Services:$(NC)"
	@cd $(DOCKER_DIR) && docker-compose ps
	@echo ""
	@echo "$(YELLOW)Build Artifacts:$(NC)"
	@if [ -f "$(AUTH_JAR)" ]; then echo "$(GREEN)✓$(NC) Auth JAR: $(AUTH_JAR)"; else echo "$(RED)✗$(NC) Auth JAR not built"; fi
	@if [ -f "$(LOADER_JAR)" ]; then echo "$(GREEN)✓$(NC) Loader JAR: $(LOADER_JAR)"; else echo "$(RED)✗$(NC) Loader JAR not built"; fi
	@if [ -f "$(PROTECTOR_JAR)" ]; then echo "$(GREEN)✓$(NC) Protector JAR: $(PROTECTOR_JAR)"; else echo "$(RED)✗$(NC) Protector JAR not built"; fi
	@echo ""

check-keys: ## Check if E2EE keys are synchronized
	@echo "$(BLUE)→ Checking E2EE key synchronization...$(NC)"
	@if docker exec nebeniac-auth test -f /app/keys/server_public_key.json; then \
		echo "$(GREEN)✓$(NC) Server has public key"; \
	else \
		echo "$(RED)✗$(NC) Server missing public key"; \
	fi
	@if [ -f "$(LOADER_DIR)/src/main/resources/server_public_key.json" ]; then \
		echo "$(GREEN)✓$(NC) Loader has public key"; \
	else \
		echo "$(RED)✗$(NC) Loader missing public key"; \
	fi
	@echo ""
	@echo "$(YELLOW)To synchronize keys, run:$(NC) make sync-keys"
