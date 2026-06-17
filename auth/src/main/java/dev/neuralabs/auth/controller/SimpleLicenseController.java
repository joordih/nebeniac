package dev.neuralabs.auth.controller;

import com.google.gson.Gson;
import dev.neuralabs.auth.util.GsonUtil;
import dev.neuralabs.auth.crypto.E2EEDecryptionService;
import dev.neuralabs.auth.crypto.KeyEncryptionService;
import dev.neuralabs.auth.database.DatabaseConnection;
import dev.neuralabs.auth.database.DatabaseInterface;
import dev.neuralabs.auth.model.Activation;
import dev.neuralabs.auth.model.AuditLog;
import dev.neuralabs.auth.model.License;
import dev.neuralabs.auth.model.Session;
import dev.neuralabs.auth.security.RateLimiter;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import spark.Request;
import spark.Response;

@Slf4j
public class SimpleLicenseController {

    private final DatabaseInterface database;
    private final Gson gson;
    private final E2EEDecryptionService e2eeService;
    private final KeyEncryptionService keyEncryptionService;

    // SECURITY: Rate limiters to prevent brute force and DoS attacks
    private final RateLimiter verificationRateLimiter;
    private final RateLimiter licenseRateLimiter;

    public SimpleLicenseController() {
        this.database = DatabaseConnection.getInstance().getDatabase();
        this.gson = GsonUtil.build();

        this.keyEncryptionService = new KeyEncryptionService();
        E2EEDecryptionService tempE2EE = null;
        try {
            tempE2EE = new E2EEDecryptionService();
            log.info(
                    "E2EE Decryption Service initialized successfully in SimpleLicenseController");
        } catch (Exception e) {
            log.error(
                    "Failed to initialize E2EE service: {}. E2EE will be disabled.",
                    e.getMessage());
        }
        this.e2eeService = tempE2EE;

        // Initialize rate limiters
        this.verificationRateLimiter = RateLimiter.Factory.forLicenseVerification();
        this.licenseRateLimiter = RateLimiter.Factory.forAuthentication();
    }

    public String verifyLicense(Request request, Response response) {
        response.type("application/json");

        // SECURITY: Apply rate limiting by IP address
        String clientIp = request.ip();
        if (!verificationRateLimiter.tryConsume(clientIp)) {
            log.warn("Rate limit exceeded for IP: {}", clientIp);
            response.status(429); // Too Many Requests
            return gson.toJson(
                    Map.of(
                            "success", false,
                            "error", "Too many requests. Please try again later.",
                            "retryAfter", 60));
        }

        try {
            String requestBody = request.body();
            VerifyRequest verifyRequest;

            boolean e2eeEnabled = e2eeService != null && e2eeService.isReady();
            if (e2eeEnabled) {
                if (!isEncryptedPayload(requestBody)) {
                    log.warn("Received plaintext license verification request while E2EE is enabled");
                    return error(response, 415, "Encrypted payload required");
                }
                try {
                    log.debug("Detected E2EE encrypted request, attempting to decrypt");
                    String decryptedData = e2eeService.decryptToString(requestBody);
                    verifyRequest = gson.fromJson(decryptedData, VerifyRequest.class);
                    log.info("Successfully decrypted E2EE license verification request");
                } catch (E2EEDecryptionService.E2EEException e) {
                    log.error("Failed to decrypt E2EE payload: {}", e.getMessage());
                    return error(response, 400, "Failed to decrypt request: " + e.getMessage());
                }
            } else {
                log.debug("Processing plaintext license verification request (E2EE unavailable)");
                verifyRequest = gson.fromJson(requestBody, VerifyRequest.class);
            }

            if (verifyRequest == null || verifyRequest.getLicenseKey() == null) {
                return error(response, 400, "License key required");
            }

            // SECURITY: Apply per-license rate limiting to prevent brute force
            String licenseKey = verifyRequest.getLicenseKey();
            if (!licenseRateLimiter.tryConsume(licenseKey)) {
                log.warn("Rate limit exceeded for license key: {}", maskLicenseKey(licenseKey));
                response.status(429);
                return gson.toJson(
                        Map.of(
                                "success", false,
                                "error", "Too many verification attempts for this license.",
                                "retryAfter", 60));
            }

            License license = database.findLicenseByKey(licenseKey);
            if (license == null) {
                logAuditEvent(
                        "LICENSE_VERIFICATION",
                        licenseKey,
                        request.ip(),
                        false,
                        "License not found");
                return error(response, 404, "License not found");
            }

            if (!license.canBeUsed()) {
                logAuditEvent(
                        "LICENSE_VERIFICATION",
                        verifyRequest.getLicenseKey(),
                        request.ip(),
                        false,
                        "License inactive or expired");
                return error(response, 403, "License inactive or expired");
            }

            List<Activation> activations = database.findActivationsByLicenseKey(
                    verifyRequest.getLicenseKey());
            Activation existingActivation = activations
                    .stream()
                    .filter(a -> a
                            .getHardwareFingerprint()
                            .equals(verifyRequest.getHardwareFingerprint()))
                    .findFirst()
                    .orElse(null);

            if (existingActivation == null) {
                if (activations.size() >= license.getMaxActivations()) {
                    logAuditEvent(
                            "LICENSE_VERIFICATION",
                            verifyRequest.getLicenseKey(),
                            request.ip(),
                            false,
                            "Maximum activations reached");
                    return error(response, 403, "Maximum activations reached");
                }

                Activation newActivation = Activation.builder()
                        .licenseKey(verifyRequest.getLicenseKey())
                        .hardwareFingerprint(verifyRequest.getHardwareFingerprint())
                        .serverName(
                                verifyRequest.getServerInfo() != null
                                        ? verifyRequest.getServerInfo().getServerName()
                                        : "Unknown")
                        .serverIp(request.ip())
                        .activatedAt(Date.from(Instant.now()))
                        .lastSeenAt(Date.from(Instant.now()))
                        .active(true)
                        .build();

                try {
                    database.saveActivation(newActivation);
                    log.info(
                            "New activation created for license: {}",
                            verifyRequest.getLicenseKey());
                } catch (Exception e) {
                    // Handle any duplicate key error or MongoDB exception
                    if (e.toString().contains("E11000") || e.toString().contains("duplicate")) {
                        log.info("Activation already exists for license {} and hardware {}, updating last seen", 
                                maskLicenseKey(verifyRequest.getLicenseKey()), 
                                verifyRequest.getHardwareFingerprint().substring(0, 8) + "...");
                        // Re-fetch the existing activation
                        activations = database.findActivationsByLicenseKey(verifyRequest.getLicenseKey());
                        existingActivation = activations
                            .stream()
                            .filter(a -> a.getHardwareFingerprint().equals(verifyRequest.getHardwareFingerprint()))
                            .findFirst()
                            .orElse(null);
                        if (existingActivation != null) {
                            existingActivation.setLastSeenAt(Date.from(Instant.now()));
                            database.saveActivation(existingActivation);
                        }
                    } else {
                        log.error("Unexpected error saving activation: ", e);
                        throw e; // Re-throw if it's not a duplicate error
                    }
                }
            } else {
                existingActivation.setLastSeenAt(Date.from(Instant.now()));
                database.saveActivation(existingActivation);
            }

            String sessionToken = generateSessionToken();
            Session session = Session.builder()
                    .sessionToken(sessionToken)
                    .licenseKey(verifyRequest.getLicenseKey())
                    .hardwareFingerprint(verifyRequest.getHardwareFingerprint())
                    .createdAt(Date.from(Instant.now()))
                    .lastHeartbeat(Date.from(Instant.now()))
                    .expiresAt(Date.from(Instant.now().plusSeconds(3600)))
                    .active(true)
                    .clientIp(request.ip())
                    .userAgent(request.userAgent())
                    .build();

            database.saveSession(session);

            logAuditEvent(
                    "LICENSE_VERIFICATION",
                    verifyRequest.getLicenseKey(),
                    request.ip(),
                    true,
                    "Verification successful");

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("success", true);
            responseData.put("sessionToken", sessionToken);
            responseData.put("expiresIn", 3600);
            responseData.put("features", license.getFeatures());
            responseData.put("licenseType", license.getLicenseType());

            return gson.toJson(responseData);
        } catch (Exception e) {
            log.error("Error verifying license", e);
            return error(response, 500, "Internal server error");
        }
    }

    public String heartbeat(Request request, Response response) {
        response.type("application/json");

        try {
            HeartbeatRequest heartbeatRequest = gson.fromJson(
                    request.body(),
                    HeartbeatRequest.class);

            if (heartbeatRequest == null ||
                    heartbeatRequest.getSessionToken() == null) {
                return error(response, 400, "Session token required");
            }

            Session session = database.findSessionByToken(
                    heartbeatRequest.getSessionToken());
            if (session == null || !session.isActive()) {
                return error(response, 404, "Session not found or inactive");
            }

            session.setLastHeartbeat(Date.from(Instant.now()));
            database.saveSession(session);

            return gson.toJson(
                    Map.of("success", true, "message", "Heartbeat received"));
        } catch (Exception e) {
            log.error("Error processing heartbeat", e);
            return error(response, 500, "Internal server error");
        }
    }

    public String getLicenseInfo(Request request, Response response) {
        response.type("application/json");

        try {
            String licenseKey = request.params(":key");
            License license = database.findLicenseByKey(licenseKey);

            if (license == null) {
                return error(response, 404, "License not found");
            }

            return gson.toJson(Map.of("success", true, "license", license));
        } catch (Exception e) {
            log.error("Error fetching license information", e);
            return error(response, 500, "Internal server error");
        }
    }

    public String getAllLicenses(Request request, Response response) {
        response.type("application/json");

        try {
            List<License> licenses = database.findAllLicenses();
            return gson.toJson(
                    Map.of(
                            "success",
                            true,
                            "licenses",
                            licenses,
                            "total",
                            licenses.size()));
        } catch (Exception e) {
            log.error("Error fetching all licenses", e);
            return error(response, 500, "Internal server error");
        }
    }

    public String createLicense(Request request, Response response) {
        response.type("application/json");

        try {
            License license = gson.fromJson(request.body(), License.class);

            if (license.getLicenseKey() == null ||
                    license.getLicenseKey().isEmpty()) {
                license.setLicenseKey(generateUniqueLicenseKey());
            }

            license.setCreatedAt(Date.from(Instant.now()));
            license.setActive(true);
            if (license.getPerLicenseSalt() == null || license.getPerLicenseSalt().isEmpty()) {
                license.setPerLicenseSalt(generatePerLicenseSalt());
            }
            if (license.getEncryptionKey() != null && !license.getEncryptionKey().isEmpty()) {
                license.setEncryptionKey(wrapEncryptionKey(license.getEncryptionKey()));
            }

            database.saveLicense(license);
            log.info("License created: {}", license.getLicenseKey());

            return gson.toJson(Map.of("success", true, "license", license));
        } catch (Exception e) {
            log.error("Error creating license", e);
            return error(response, 500, "Error creating license");
        }
    }

    public String updateLicense(Request request, Response response) {
        response.type("application/json");

        try {
            String licenseKey = request.params(":key");
            License existingLicense = database.findLicenseByKey(licenseKey);

            if (existingLicense == null) {
                return error(response, 404, "License not found");
            }

            License updatedLicense = gson.fromJson(
                    request.body(),
                    License.class);
            updatedLicense.setLicenseKey(licenseKey);
            if (updatedLicense.getPerLicenseSalt() == null || updatedLicense.getPerLicenseSalt().isEmpty()) {
                updatedLicense.setPerLicenseSalt(existingLicense.getPerLicenseSalt() != null
                        ? existingLicense.getPerLicenseSalt()
                        : generatePerLicenseSalt());
            }
            if (updatedLicense.getEncryptionKey() != null && !updatedLicense.getEncryptionKey().isEmpty()) {
                updatedLicense.setEncryptionKey(wrapEncryptionKey(updatedLicense.getEncryptionKey()));
            } else {
                updatedLicense.setEncryptionKey(existingLicense.getEncryptionKey());
            }

            database.saveLicense(updatedLicense);

            return gson.toJson(
                    Map.of("success", true, "license", updatedLicense));
        } catch (Exception e) {
            log.error("Error updating license", e);
            return error(response, 500, "Error updating license");
        }
    }

    public String deleteLicense(Request request, Response response) {
        response.type("application/json");

        try {
            String licenseKey = request.params(":key");
            database.deleteLicense(licenseKey);

            return gson.toJson(
                    Map.of("success", true, "message", "License deleted"));
        } catch (Exception e) {
            log.error("Error deleting license", e);
            return error(response, 500, "Error deleting license");
        }
    }

    public String getStatistics(Request request, Response response) {
        response.type("application/json");

        try {
            long totalLicenses = database.findAllLicenses().size();
            Map<String, Object> stats = Map.of("totalLicenses", totalLicenses);

            return gson.toJson(Map.of("success", true, "statistics", stats));
        } catch (Exception e) {
            log.error("Error fetching statistics", e);
            return error(response, 500, "Error retrieving statistics");
        }
    }

    public String generateNewLicense(Request request, Response response) {
        response.type("application/json");

        try {
            GenerateLicenseRequest genRequest = gson.fromJson(
                    request.body(),
                    GenerateLicenseRequest.class);

            License license = License.builder()
                    .licenseKey(generateUniqueLicenseKey())
                    .customerEmail(genRequest.getUserId() + "@nebeniac.local")
                    .pluginId(genRequest.getPluginId())
                    .licenseType("STANDARD")
                    .maxActivations(1)
                    .active(true)
                    .createdAt(Date.from(Instant.now()))
                    .expiresAt(genRequest.getExpiresAt())
                    .perLicenseSalt(generatePerLicenseSalt())
                    .encryptionMetadata(
                            genRequest.getMetadata() != null
                                    ? genRequest.getMetadata()
                                    : new HashMap<>())
                    .features(Arrays.asList("BASIC"))
                    .build();

            database.saveLicense(license);
            log.info("New license generated: {}", license.getLicenseKey());

            return gson.toJson(Map.of("success", true, "license", license));
        } catch (Exception e) {
            log.error("Error generating new license", e);
            return error(response, 500, "Error generating license");
        }
    }

    public String getUserLicenses(Request request, Response response) {
        response.type("application/json");

        try {
            String userId = request.params(":userId");
            String userEmail = userId + "@nebeniac.local";
            List<License> allLicenses = database.findAllLicenses();
            List<License> licenses = allLicenses
                    .stream()
                    .filter(license -> userEmail.equals(license.getCustomerEmail()))
                    .collect(Collectors.toList());

            return gson.toJson(
                    Map.of(
                            "success",
                            true,
                            "licenses",
                            licenses,
                            "total",
                            licenses.size()));
        } catch (Exception e) {
            log.error("Error fetching user licenses", e);
            return error(response, 500, "Error fetching user licenses");
        }
    }

    public String getPublicKey(Request request, Response response) {
        response.type("application/json");

        try {
            if (e2eeService == null || !e2eeService.isReady()) {
                return error(response, 503, "E2EE service not available");
            }

            String publicKeyJson = e2eeService.getPublicKeyJson();
            return gson.toJson(
                    Map.of(
                            "success",
                            true,
                            "publicKey",
                            publicKeyJson,
                            "keyPath",
                            e2eeService.getPublicKeyFilePath(),
                            "version",
                            "1.0"));
        } catch (Exception e) {
            log.error("Error getting public key", e);
            return error(response, 500, "Failed to retrieve public key");
        }
    }

    public String getE2EEStats(Request request, Response response) {
        response.type("application/json");

        try {
            if (e2eeService == null) {
                return gson.toJson(
                        Map.of(
                                "success",
                                false,
                                "error",
                                "E2EE service not initialized"));
            }

            Map<String, Object> stats = e2eeService.getStats();
            return gson.toJson(Map.of("success", true, "stats", stats));
        } catch (Exception e) {
            log.error("Error getting E2EE stats", e);
            return error(response, 500, "Failed to retrieve stats");
        }
    }

    private boolean isEncryptedPayload(String body) {
        if (body == null || body.isEmpty()) {
            return false;
        }

        return (body.contains("\"ciphertext\"") && body.contains("\"timestamp\""));
    }

    private void logAuditEvent(
            String eventType,
            String licenseKey,
            String ipAddress,
            boolean success,
            String details) {
        try {
            AuditLog auditLog = AuditLog.builder()
                    .event(eventType)
                    .licenseKey(licenseKey)
                    .clientIp(ipAddress)
                    .timestamp(Date.from(Instant.now()))
                    .success(success)
                    .message(details)
                    .build();

            database.saveAuditLog(auditLog);
        } catch (Exception e) {
            log.error("Error saving audit event", e);
        }
    }

    private String generateSessionToken() {
        return UUID.randomUUID().toString();
    }

    private String wrapEncryptionKey(String plaintextKey) {
        if (plaintextKey == null || plaintextKey.isEmpty()) {
            return null;
        }
        return keyEncryptionService.wrapKey(plaintextKey);
    }

    private String generatePerLicenseSalt() {
        byte[] salt = new byte[32];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    private String generateUniqueLicenseKey() {
        return ("LIC-" +
                UUID.randomUUID().toString().toUpperCase().substring(0, 8) +
                "-" +
                UUID.randomUUID().toString().toUpperCase().substring(0, 8));
    }

    // SECURITY: Mask license key for logging to prevent exposure
    private String maskLicenseKey(String licenseKey) {
        if (licenseKey == null || licenseKey.length() < 8) {
            return "***";
        }
        return licenseKey.substring(0, 4) + "***" + licenseKey.substring(licenseKey.length() - 4);
    }

    private String error(Response response, int status, String message) {
        response.status(status);
        return gson.toJson(Map.of("success", false, "error", message));
    }

    public static class VerifyRequest {

        private String licenseKey;
        private String hardwareFingerprint;
        private ServerInfo serverInfo;
        private String pluginVersion;
        private long clientTimestamp;

        public String getLicenseKey() {
            return licenseKey;
        }

        public void setLicenseKey(String licenseKey) {
            this.licenseKey = licenseKey;
        }

        public String getHardwareFingerprint() {
            return hardwareFingerprint;
        }

        public void setHardwareFingerprint(String hardwareFingerprint) {
            this.hardwareFingerprint = hardwareFingerprint;
        }

        public ServerInfo getServerInfo() {
            return serverInfo;
        }

        public void setServerInfo(ServerInfo serverInfo) {
            this.serverInfo = serverInfo;
        }

        public String getPluginVersion() {
            return pluginVersion;
        }

        public void setPluginVersion(String pluginVersion) {
            this.pluginVersion = pluginVersion;
        }

        public long getClientTimestamp() {
            return clientTimestamp;
        }

        public void setClientTimestamp(long clientTimestamp) {
            this.clientTimestamp = clientTimestamp;
        }
    }

    public static class ServerInfo {

        private String serverName;
        private int serverPort;
        private String minecraftVersion;
        private String serverSoftware;

        public String getServerName() {
            return serverName;
        }

        public void setServerName(String serverName) {
            this.serverName = serverName;
        }

        public int getServerPort() {
            return serverPort;
        }

        public void setServerPort(int serverPort) {
            this.serverPort = serverPort;
        }

        public String getMinecraftVersion() {
            return minecraftVersion;
        }

        public void setMinecraftVersion(String minecraftVersion) {
            this.minecraftVersion = minecraftVersion;
        }

        public String getServerSoftware() {
            return serverSoftware;
        }

        public void setServerSoftware(String serverSoftware) {
            this.serverSoftware = serverSoftware;
        }
    }

    public static class HeartbeatRequest {

        private String sessionToken;
        private String licenseKey;
        private String hardwareFingerprint;
        private long clientTimestamp;

        public String getSessionToken() {
            return sessionToken;
        }

        public void setSessionToken(String sessionToken) {
            this.sessionToken = sessionToken;
        }

        public String getLicenseKey() {
            return licenseKey;
        }

        public void setLicenseKey(String licenseKey) {
            this.licenseKey = licenseKey;
        }

        public String getHardwareFingerprint() {
            return hardwareFingerprint;
        }

        public void setHardwareFingerprint(String hardwareFingerprint) {
            this.hardwareFingerprint = hardwareFingerprint;
        }

        public long getClientTimestamp() {
            return clientTimestamp;
        }

        public void setClientTimestamp(long clientTimestamp) {
            this.clientTimestamp = clientTimestamp;
        }
    }

    public static class GenerateLicenseRequest {

        private String userId;
        private String pluginId;
        private String pluginVersion;
        private Date expiresAt;
        private Map<String, Object> metadata;

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getPluginId() {
            return pluginId;
        }

        public void setPluginId(String pluginId) {
            this.pluginId = pluginId;
        }

        public String getPluginVersion() {
            return pluginVersion;
        }

        public void setPluginVersion(String pluginVersion) {
            this.pluginVersion = pluginVersion;
        }

        public Date getExpiresAt() {
            return expiresAt;
        }

        public void setExpiresAt(Date expiresAt) {
            this.expiresAt = expiresAt;
        }

        public Map<String, Object> getMetadata() {
            return metadata;
        }

        public void setMetadata(Map<String, Object> metadata) {
            this.metadata = metadata;
        }
    }
}
