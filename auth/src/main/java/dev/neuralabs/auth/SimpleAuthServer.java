package dev.neuralabs.auth;

import static spark.Spark.*;

import dev.neuralabs.auth.config.AuthConfig;
import dev.neuralabs.auth.controller.*;
import dev.neuralabs.auth.crypto.TinkE2EEManager;
import dev.neuralabs.auth.database.DatabaseConnection;
import java.io.File;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SimpleAuthServer {

    private static final String API_PREFIX = "/api/v1";

    public static void main(String[] args) {
        log.info("Starting Nebeniac Authentication Server (Local)...");

        try {
            AuthConfig config = AuthConfig.getInstance();
            int port = config.getServerPort();

            if (args.length > 0) {
                try {
                    port = Integer.parseInt(args[0]);
                } catch (NumberFormatException e) {
                    log.warn(
                        "Invalid port in arguments, using configured port: {}",
                        port
                    );
                }
            }

            initializeComponents();
            configureServer(port);
            setupRoutes();

            Runtime.getRuntime().addShutdownHook(
                new Thread(SimpleAuthServer::shutdown)
            );

            System.out.printf(
                "Authentication Server iniciado correctamente en puerto %d%n",
                port
            );
            log.info(
                "Authentication Server iniciado correctamente en puerto {}",
                port
            );
            System.out.printf(
                "API disponible en: http://localhost:%d%s%n",
                port,
                API_PREFIX
            );
            log.info(
                "API disponible en: http://localhost:{}{}",
                port,
                API_PREFIX
            );
        } catch (Exception e) {
            log.error("Error starting Authentication Server", e);
            shutdown();
            System.exit(1);
        }
    }

    private static void initializeComponents() {
        log.info("Inicializando componentes...");

        DatabaseConnection.getInstance().initialize();

       
        initializeE2EE();

        log.info("Componentes inicializados correctamente");
    }

    private static void initializeE2EE() {
        try {
            log.info("Initializing E2EE system...");

           
            File keysDir = new File("keys");
            if (!keysDir.exists()) {
                keysDir.mkdirs();
                log.info("Keys directory created: keys/");
            }

           
            File privateKeyFile = new File("keys/server_private_key.json");
            File publicKeyFile = new File("keys/server_public_key.json");

            if (privateKeyFile.exists() && publicKeyFile.exists()) {
                log.info("E2EE keys found in: keys/");
            } else {
                log.info(
                    "E2EE keys not found, generating new keys..."
                );
            }

           
            TinkE2EEManager e2eeManager = new TinkE2EEManager();

            if (e2eeManager.isInitialized()) {
                log.info("E2EE system initialized successfully");
                log.info("  - Private key: keys/server_private_key.json");
                log.info("  - Public key: keys/server_public_key.json");
                log.info("");
                log.info(
                    "To use E2EE in clients, copy the public key:"
                );
                log.info(
                    "   cp keys/server_public_key.json <client>/src/main/resources/"
                );
                log.info("");
            } else {
                log.warn("E2EE system initialized but not ready");
            }
        } catch (Exception e) {
            log.error("Error initializing E2EE system: {}", e.getMessage());
            log.warn(
                "Server will continue without E2EE. Clients will use plaintext communication."
            );
            log.warn(
                "To enable E2EE, fix the error and restart the server."
            );
        }
    }

    private static void configureServer(int port) {
        port(port);

        AuthConfig config = AuthConfig.getInstance();

        before("/*", (request, response) -> {
            response.header("Content-Type", "application/json");

            if (config.isCorsEnabled()) {
                response.header(
                    "Access-Control-Allow-Origin",
                    config.getCorsAllowedOrigins()
                );
                response.header(
                    "Access-Control-Allow-Methods",
                    config.getCorsAllowedMethods()
                );
                response.header(
                    "Access-Control-Allow-Headers",
                    config.getCorsAllowedHeaders()
                );
            }

            if (config.isRequestLoggingEnabled()) {
                log.debug(
                    "Request: {} {} from {}",
                    request.requestMethod(),
                    request.pathInfo(),
                    request.ip()
                );
            }
        });

        options("/*", (request, response) -> {
            String accessControlRequestHeaders = request.headers(
                "Access-Control-Request-Headers"
            );
            if (accessControlRequestHeaders != null) {
                response.header(
                    "Access-Control-Allow-Headers",
                    accessControlRequestHeaders
                );
            }

            String accessControlRequestMethod = request.headers(
                "Access-Control-Request-Method"
            );
            if (accessControlRequestMethod != null) {
                response.header(
                    "Access-Control-Allow-Methods",
                    accessControlRequestMethod
                );
            }

            return "OK";
        });

        log.info("Server configured on port {}", port);
    }

    private static void setupRoutes() {
        SimpleLicenseController licenseController =
            new SimpleLicenseController();
        PluginController pluginController = new PluginController();
        AuthController authController = new AuthController();
        UserController userController = new UserController();
        SetupController setupController = new SetupController();

        path(API_PREFIX, () -> {
            post("/verify", licenseController::verifyLicense);
            post("/heartbeat", licenseController::heartbeat);
            get("/license/:key", licenseController::getLicenseInfo);

            get("/licenses", licenseController::getAllLicenses);
            post("/licenses", licenseController::createLicense);
            put("/licenses/:key", licenseController::updateLicense);
            delete("/licenses/:key", licenseController::deleteLicense);
            get("/statistics", licenseController::getStatistics);

            post("/licenses/generate", licenseController::generateNewLicense);
            get("/licenses/user/:userId", licenseController::getUserLicenses);

           
            get("/e2ee/public-key", licenseController::getPublicKey);
            get("/e2ee/stats", licenseController::getE2EEStats);

            get("/plugins", pluginController::listPlugins);
            post("/plugins", pluginController::registerPlugin);

            get("/plugins/available", pluginController::getAvailablePlugins);

            get("/plugins/:id", pluginController::getPlugin);
            put("/plugins/:id", pluginController::updatePlugin);
            delete("/plugins/:id", pluginController::deletePlugin);
            post("/plugins/metadata", pluginController::getPluginMetadata);
            post(
                "/plugins/:pluginId/download",
                pluginController::downloadProtectedPlugin
            );
            get(
                "/plugins/:pluginId/download/:licenseKey",
                pluginController::downloadEncryptedPlugin
            );
            post(
                "/plugins/:pluginId/encrypt",
                pluginController::encryptPluginRealTime
            );
            post(
                "/plugins/:pluginId/encrypt-docker",
                pluginController::startDockerEncryption
            );
            get(
                "/plugins/signature/public-key",
                pluginController::getSignaturePublicKey
            );

            post("/auth/login", authController::login);
            post("/auth/logout", authController::logout);
            post(
                "/auth/complete-registration",
                authController::completeRegistration
            );
            post(
                "/auth/request-password-reset",
                authController::requestPasswordReset
            );
            post("/auth/reset-password", authController::resetPassword);
            get("/auth/verify", authController::verifyToken);

            get("/users", userController::getAllUsers);
            get("/users/search", userController::searchUsers);
            post("/users", userController::createUser);
            get("/users/:id", userController::getUser);
            put("/users/:id", userController::updateUser);
            delete("/users/:id", userController::deleteUser);
            post(
                "/users/:id/resend-invitation",
                userController::resendInvitation
            );

            get("/setup/status", setupController::getSetupStatus);
            post("/setup/admin", setupController::createFirstAdmin);
            post("/setup/admin/default", setupController::createDefaultAdmin);

            get("/email/status", setupController::getEmailStatus);
            post("/email/test", setupController::sendTestEmail);
            post("/email/test-invitation", userController::sendTestInvitation);
        });

        get("/health", (request, response) -> {
            response.type("application/json");
            DatabaseConnection dbConnection = DatabaseConnection.getInstance();
            boolean healthy = dbConnection.isHealthy();
            String dbType = dbConnection.getDatabaseType();

            if (healthy) {
                response.status(200);
                return String.format(
                    "{\"status\":\"healthy\",\"database\":\"connected\",\"databaseType\":\"%s\"}",
                    dbType
                );
            } else {
                response.status(503);
                return String.format(
                    "{\"status\":\"unhealthy\",\"database\":\"disconnected\",\"databaseType\":\"%s\"}",
                    dbType
                );
            }
        });

        notFound((request, response) -> {
            response.type("application/json");
            response.status(404);
            return "{\"error\":\"Endpoint not found\"}";
        });

        internalServerError((request, response) -> {
            response.type("application/json");
            response.status(500);
            return "{\"error\":\"Internal server error\"}";
        });

        log.info("Routes configured successfully");
    }

    public static void shutdown() {
        log.info("Cerrando Authentication Server...");

        stop();
        DatabaseConnection.getInstance().close();

        log.info("Authentication Server cerrado correctamente");
    }
}
