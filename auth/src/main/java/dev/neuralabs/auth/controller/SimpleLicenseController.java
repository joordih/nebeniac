package dev.neuralabs.auth.controller;

import static dev.neuralabs.auth.controller.ControllerSupport.bearerClaims;
import static dev.neuralabs.auth.controller.ControllerSupport.error;
import static dev.neuralabs.auth.controller.ControllerSupport.isEncryptedPayload;
import static dev.neuralabs.auth.controller.ControllerSupport.maskLicenseKey;

import com.google.gson.Gson;
import dev.neuralabs.auth.crypto.DecryptedPayload;
import dev.neuralabs.auth.crypto.E2EEDecryptionService;
import dev.neuralabs.auth.crypto.E2EEResponseEncryption;
import dev.neuralabs.auth.database.DatabaseConnection;
import dev.neuralabs.auth.database.DatabaseInterface;
import dev.neuralabs.auth.model.Activation;
import dev.neuralabs.auth.model.AuditLog;
import dev.neuralabs.auth.model.License;
import dev.neuralabs.auth.model.Session;
import dev.neuralabs.auth.security.RateLimiter;
import dev.neuralabs.auth.util.GsonUtil;
import dev.neuralabs.auth.util.JWTUtil;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import spark.Request;
import spark.Response;

@Slf4j
public class SimpleLicenseController {
    private final DatabaseInterface database;
    private final Gson gson;
    private final E2EEDecryptionService e2eeService;
    private final E2EEResponseEncryption responseEncryption;

    private final RateLimiter verificationRateLimiter;
    private final RateLimiter licenseRateLimiter;

    public SimpleLicenseController(
            E2EEDecryptionService e2eeService,
            E2EEResponseEncryption responseEncryption) {
        this.database = DatabaseConnection.getInstance().getDatabase();
        this.gson = GsonUtil.buildApi();
        this.e2eeService = e2eeService;
        this.responseEncryption = responseEncryption;

        this.verificationRateLimiter = RateLimiter.Factory.forLicenseVerification();
        this.licenseRateLimiter = RateLimiter.Factory.forAuthentication();
    }

    public String verifyLicense(Request request, Response response) {
        String clientIp = request.ip();
        if (!verificationRateLimiter.tryConsume(clientIp)) {
            log.warn("Rate limit exceeded for IP: {}", clientIp);
            response.status(429);
            return gson.toJson(
                    Map.of(
                            "success", false,
                            "error", "Too many requests. Please try again later.",
                            "retryAfter", 60));
        }

        try {
            if (e2eeService == null || !e2eeService.isReady()) {
                return error(response, 503, "E2EE service not available");
            }

            String requestBody = request.body();
            if (!isEncryptedPayload(requestBody)) {
                log.warn("Rejected plaintext license verification request from {}", clientIp);
                return error(response, 415, "Encrypted payload required");
            }

            DecryptedPayload payload;
            try {
                payload = e2eeService.decryptRequest(requestBody);
            } catch (E2EEDecryptionService.E2EEException e) {
                log.warn("Failed to decrypt license verification request: {}", e.getMessage());
                return error(response, 400, "Failed to decrypt request");
            }
            VerifyRequest verifyRequest = gson.fromJson(payload.getData(), VerifyRequest.class);

            if (verifyRequest == null || verifyRequest.getLicenseKey() == null) {
                return error(response, 400, "License key required");
            }
            if (verifyRequest.getHardwareFingerprint() == null || verifyRequest.getHardwareFingerprint().isBlank()) {
                return error(response, 400, "Hardware fingerprint required");
            }

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
                    .filter(a -> verifyRequest.getHardwareFingerprint().equals(a.getHardwareFingerprint()))
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
                    if (e.toString().contains("E11000") || e.toString().contains("duplicate")) {
                        log.info("Activation already exists for license {} and hardware {}, updating last seen",
                                maskLicenseKey(verifyRequest.getLicenseKey()),
                                verifyRequest.getHardwareFingerprint().substring(0, 8) + "...");

                        activations = database.findActivationsByLicenseKey(verifyRequest.getLicenseKey());
                        existingActivation = activations
                            .stream()
                            .filter(a -> verifyRequest.getHardwareFingerprint().equals(a.getHardwareFingerprint()))
                            .findFirst()
                            .orElse(null);
                        if (existingActivation != null) {
                            existingActivation.setLastSeenAt(Date.from(Instant.now()));
                            database.saveActivation(existingActivation);
                        }
                    } else {
                        log.error("Unexpected error saving activation: ", e);
                        throw e;
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

            return responseEncryption.encryptResponse(responseData, payload);
        } catch (Exception e) {
            log.error("Error verifying license", e);
            return error(response, 500, "Internal server error");
        }
    }

    public String heartbeat(Request request, Response response) {
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
            if (session == null || !session.isValid()) {
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
        try {
            LicenseRequest licenseRequest = gson.fromJson(request.body(), LicenseRequest.class);
            if (licenseRequest == null || licenseRequest.getCustomerEmail() == null
                    || licenseRequest.getCustomerEmail().isBlank()) {
                return error(response, 400, "Customer email required");
            }

            License license = License.builder()
                    .licenseKey(generateUniqueLicenseKey())
                    .createdAt(Date.from(Instant.now()))
                    .active(true)
                    .build();
            licenseRequest.applyTo(license);

            database.saveLicense(license);
            log.info("License created: {}", maskLicenseKey(license.getLicenseKey()));

            return gson.toJson(Map.of("success", true, "license", license));
        } catch (Exception e) {
            log.error("Error creating license", e);
            return error(response, 500, "Error creating license");
        }
    }

    public String updateLicense(Request request, Response response) {
        try {
            String licenseKey = request.params(":key");
            License license = database.findLicenseByKey(licenseKey);

            if (license == null) {
                return error(response, 404, "License not found");
            }

            LicenseRequest licenseRequest = gson.fromJson(request.body(), LicenseRequest.class);
            if (licenseRequest == null) {
                return error(response, 400, "License data required");
            }
            licenseRequest.applyTo(license);
            license.setUpdatedAt(Date.from(Instant.now()));

            database.saveLicense(license);

            return gson.toJson(Map.of("success", true, "license", license));
        } catch (Exception e) {
            log.error("Error updating license", e);
            return error(response, 500, "Error updating license");
        }
    }

    public String deleteLicense(Request request, Response response) {
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
        try {
            String userId = request.params(":userId");
            JWTUtil.JWTClaims claims = bearerClaims(request);
            if (!claims.isAdmin() && !claims.getUserId().equals(userId)) {
                return error(response, 403, "Insufficient permissions");
            }
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
                            "version",
                            "1.0"));
        } catch (Exception e) {
            log.error("Error getting public key", e);
            return error(response, 500, "Failed to retrieve public key");
        }
    }

    public String getE2EEStats(Request request, Response response) {
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

    private String generateUniqueLicenseKey() {
        return ("LIC-" +
                UUID.randomUUID().toString().toUpperCase().substring(0, 8) +
                "-" +
                UUID.randomUUID().toString().toUpperCase().substring(0, 8));
    }

    @Getter
    @Setter
    public static class VerifyRequest {
        private String licenseKey;
        private String hardwareFingerprint;
        private ServerInfo serverInfo;
        private String pluginVersion;
        private long clientTimestamp;
    }

    @Getter
    @Setter
    public static class ServerInfo {
        private String serverName;
        private int serverPort;
        private String minecraftVersion;
        private String serverSoftware;
    }

    @Getter
    @Setter
    public static class LicenseRequest {
        private String customerEmail;
        private String customerName;
        private String licenseType;
        private Integer maxActivations;
        private List<String> features;
        private Date expiresAt;
        private String notes;
        private String pluginId;
        private List<String> targetPackages;
        private Boolean active;

        void applyTo(License license) {
            if (customerEmail != null) license.setCustomerEmail(customerEmail.trim());
            if (customerName != null) license.setCustomerName(customerName);
            if (licenseType != null) license.setLicenseType(licenseType);
            if (maxActivations != null) license.setMaxActivations(Math.max(1, maxActivations));
            if (features != null) license.setFeatures(features);
            if (expiresAt != null) license.setExpiresAt(expiresAt);
            if (notes != null) license.setNotes(notes);
            if (pluginId != null) license.setPluginId(pluginId);
            if (targetPackages != null) license.setTargetPackages(targetPackages);
            if (active != null) license.setActive(active);
        }
    }

    @Getter
    @Setter
    public static class HeartbeatRequest {
        private String sessionToken;
        private String licenseKey;
        private String hardwareFingerprint;
        private long clientTimestamp;
    }

    @Getter
    @Setter
    public static class GenerateLicenseRequest {
        private String userId;
        private String pluginId;
        private String pluginVersion;
        private Date expiresAt;
        private Map<String, Object> metadata;
    }
}
