package dev.neuralabs.auth.crypto;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class E2EEServiceManager {

    private final E2EEDecryptionService decryptionService;
    private final E2EEResponseEncryption responseEncryption;
    private final E2EEKeyRotationService keyRotationService;
    private final E2EERateLimiter rateLimiter;
    private final E2EEConfig config;
    private final boolean initialized;

        public E2EEServiceManager(E2EEConfig config)
        throws GeneralSecurityException, IOException {
        this.config = config;

        log.info("Initializing E2EE Service Manager...");
        log.info(
            "Configuration: E2EE={}, ResponseEncryption={}, KeyRotation={}, RateLimit={}",
            config.isEnabled(),
            config.isResponseEncryptionEnabled(),
            config.isKeyRotationEnabled(),
            config.isRateLimitEnabled()
        );

        boolean tempInitialized = false;
        E2EEDecryptionService tempDecryption = null;
        E2EEResponseEncryption tempResponse = null;
        E2EEKeyRotationService tempRotation = null;
        E2EERateLimiter tempRateLimiter = null;

        if (config.isEnabled()) {
            try {
               
                tempDecryption = new E2EEDecryptionService();
                log.info("✓ E2EE Decryption Service initialized");

               
                if (config.isResponseEncryptionEnabled()) {
                    tempResponse = new E2EEResponseEncryption(true);
                    log.info("✓ E2EE Response Encryption initialized");
                } else {
                    tempResponse = new E2EEResponseEncryption(false);
                    log.info("○ E2EE Response Encryption disabled");
                }

               
                if (config.isKeyRotationEnabled()) {
                    tempRotation = new E2EEKeyRotationService(
                        config.getKeyRotationDays(),
                        true,
                        tempDecryption.getTinkManager()
                    );
                    log.info(
                        "✓ E2EE Key Rotation Service initialized (every {} days)",
                        config.getKeyRotationDays()
                    );
                } else {
                    log.info("○ E2EE Key Rotation disabled");
                }

               
                if (config.isRateLimitEnabled()) {
                    tempRateLimiter = new E2EERateLimiter(
                        true,
                        config.getRateLimitRequestsPerMinute()
                    );
                    log.info(
                        "✓ E2EE Rate Limiter initialized ({} req/min)",
                        config.getRateLimitRequestsPerMinute()
                    );
                } else {
                    tempRateLimiter = new E2EERateLimiter(false, 0);
                    log.info("○ E2EE Rate Limiter disabled");
                }

                tempInitialized = true;
                log.info("E2EE Service Manager initialized successfully");
            } catch (Exception e) {
                log.error(
                    "Failed to initialize E2EE Service Manager: {}",
                    e.getMessage(),
                    e
                );
                throw e;
            }
        } else {
            log.info("E2EE is disabled by configuration");
        }

        this.decryptionService = tempDecryption;
        this.responseEncryption = tempResponse;
        this.keyRotationService = tempRotation;
        this.rateLimiter = tempRateLimiter;
        this.initialized = tempInitialized;
    }

        public DecryptedPayload processEncryptedRequest(
        String encryptedBody,
        String clientIp
    ) throws E2EEException {
        if (!initialized || decryptionService == null) {
            throw new E2EEException("E2EE Service not initialized");
        }

       
        if (rateLimiter != null && rateLimiter.isEnabled()) {
            E2EERateLimiter.RateLimitResult rateLimitResult =
                rateLimiter.checkLimit(clientIp, null);

            if (!rateLimitResult.isAllowed()) {
                log.warn("Rate limit exceeded for IP: {}", clientIp);
                throw new E2EEException(
                    "Rate limit exceeded: " + rateLimitResult.getMessage()
                );
            }

            if (rateLimitResult.hasWarning()) {
                log.warn(
                    "Rate limit warning for IP {}: {}",
                    clientIp,
                    rateLimitResult.getMessage()
                );
            }
        }

       
        try {
            DecryptedPayload payload = decryptionService.decryptRequest(
                encryptedBody
            );

           
            if (
                rateLimiter != null &&
                rateLimiter.isEnabled() &&
                payload.getNonce() != null
            ) {
                E2EERateLimiter.RateLimitResult nonceCheck =
                    rateLimiter.checkLimit(clientIp, payload.getNonce());

                if (!nonceCheck.isAllowed()) {
                    throw new E2EEException("Nonce-based rate limit exceeded");
                }
            }

            return payload;
        } catch (E2EEDecryptionService.E2EEException e) {
            throw new E2EEException("Decryption failed: " + e.getMessage(), e);
        }
    }

        public String encryptResponse(Object responseData, String sessionToken) {
        if (
            !initialized ||
            responseEncryption == null ||
            !responseEncryption.isEnabled()
        ) {
           
            try {
                return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(
                    responseData
                );
            } catch (Exception e) {
                log.error("Failed to serialize response", e);
                return "{\"error\":\"Serialization failed\"}";
            }
        }

        return responseEncryption.encryptResponseAuto(
            responseData,
            sessionToken,
            null
        );
    }

        public boolean rotateKeys() {
        if (keyRotationService == null) {
            log.warn("Key rotation service not initialized");
            return false;
        }
        return keyRotationService.rotateKeys();
    }

        public String getPublicKeyJson() throws IOException {
        if (!initialized || decryptionService == null) {
            throw new IOException("E2EE Service not initialized");
        }
        return decryptionService.getPublicKeyJson();
    }

        public Map<String, Object> getComprehensiveStats() {
        Map<String, Object> stats = new HashMap<>();

        stats.put("initialized", initialized);
        stats.put("enabled", config.isEnabled());

        if (decryptionService != null) {
            stats.put("decryption", decryptionService.getStats());
        }

        if (responseEncryption != null) {
            stats.put("responseEncryption", responseEncryption.getStats());
        }

        if (keyRotationService != null) {
            E2EEKeyRotationService.KeyRotationStatus rotationStatus =
                keyRotationService.getStatus();
            Map<String, Object> rotationStats = new HashMap<>();
            rotationStats.put("enabled", rotationStatus.autoRotationEnabled);
            rotationStats.put("rotationDays", rotationStatus.rotationDays);
            rotationStats.put(
                "lastRotation",
                rotationStatus.lastRotation.toString()
            );
            rotationStats.put(
                "nextRotation",
                rotationStatus.nextRotation.toString()
            );
            rotationStats.put("archivedKeys", rotationStatus.archivedKeyCount);
            rotationStats.put("overdue", rotationStatus.rotationOverdue);
            stats.put("keyRotation", rotationStats);
        }

        if (rateLimiter != null) {
            stats.put("rateLimiter", rateLimiter.getStats());
        }

        return stats;
    }

        public Map<String, Object> getRateLimitStatus(String ipAddress) {
        Map<String, Object> status = new HashMap<>();

        if (rateLimiter == null || !rateLimiter.isEnabled()) {
            status.put("enabled", false);
            status.put("limited", false);
            return status;
        }

        status.put("enabled", true);
        status.put("limited", rateLimiter.isRateLimited(ipAddress));
        status.put(
            "remainingRequests",
            rateLimiter.getRemainingRequests(ipAddress)
        );

        return status;
    }

        public void resetRateLimit(String ipAddress) {
        if (rateLimiter != null) {
            rateLimiter.resetLimit(ipAddress);
        }
    }

        public void clearSessionKey(String sessionToken) {
        if (responseEncryption != null) {
            responseEncryption.clearSessionKey(sessionToken);
        }
    }

        public boolean isReady() {
        return (
            initialized &&
            decryptionService != null &&
            decryptionService.isReady()
        );
    }

        public void shutdown() {
        log.info("Shutting down E2EE Service Manager...");

        if (decryptionService != null) {
            try {
                decryptionService.shutdown();
                log.info("✓ Decryption service stopped");
            } catch (Exception e) {
                log.error("Error stopping decryption service", e);
            }
        }

        if (keyRotationService != null) {
            try {
                keyRotationService.shutdown();
                log.info("✓ Key rotation service stopped");
            } catch (Exception e) {
                log.error("Error stopping key rotation service", e);
            }
        }

        if (rateLimiter != null) {
            try {
                rateLimiter.shutdown();
                log.info("✓ Rate limiter stopped");
            } catch (Exception e) {
                log.error("Error stopping rate limiter", e);
            }
        }

        log.info("E2EE Service Manager shutdown complete");
    }

        public static class E2EEConfig {

        private boolean enabled = true;
        private boolean responseEncryptionEnabled = true;
        private boolean keyRotationEnabled = true;
        private int keyRotationDays = 30;
        private boolean rateLimitEnabled = true;
        private int rateLimitRequestsPerMinute = 60;

        public E2EEConfig() {}

        public static E2EEConfig fromEnvironment() {
            E2EEConfig config = new E2EEConfig();

            config.enabled = getBooleanEnv("E2EE_ENABLED", true);
            config.responseEncryptionEnabled = getBooleanEnv(
                "E2EE_RESPONSE_ENCRYPTION",
                true
            );
            config.keyRotationEnabled = getBooleanEnv(
                "E2EE_KEY_ROTATION_ENABLED",
                true
            );
            config.keyRotationDays = getIntEnv("E2EE_KEY_ROTATION_DAYS", 30);
            config.rateLimitEnabled = getBooleanEnv(
                "E2EE_RATE_LIMIT_ENABLED",
                true
            );
            config.rateLimitRequestsPerMinute = getIntEnv(
                "E2EE_RATE_LIMIT_REQUESTS_PER_MINUTE",
                60
            );

            return config;
        }

        private static boolean getBooleanEnv(String key, boolean defaultValue) {
            String value = System.getenv(key);
            return value != null ? Boolean.parseBoolean(value) : defaultValue;
        }

        private static int getIntEnv(String key, int defaultValue) {
            String value = System.getenv(key);
            try {
                return value != null ? Integer.parseInt(value) : defaultValue;
            } catch (NumberFormatException e) {
                return defaultValue;
            }
        }

       
        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public boolean isResponseEncryptionEnabled() {
            return responseEncryptionEnabled;
        }

        public void setResponseEncryptionEnabled(boolean enabled) {
            this.responseEncryptionEnabled = enabled;
        }

        public boolean isKeyRotationEnabled() {
            return keyRotationEnabled;
        }

        public void setKeyRotationEnabled(boolean enabled) {
            this.keyRotationEnabled = enabled;
        }

        public int getKeyRotationDays() {
            return keyRotationDays;
        }

        public void setKeyRotationDays(int days) {
            this.keyRotationDays = days;
        }

        public boolean isRateLimitEnabled() {
            return rateLimitEnabled;
        }

        public void setRateLimitEnabled(boolean enabled) {
            this.rateLimitEnabled = enabled;
        }

        public int getRateLimitRequestsPerMinute() {
            return rateLimitRequestsPerMinute;
        }

        public void setRateLimitRequestsPerMinute(int requests) {
            this.rateLimitRequestsPerMinute = requests;
        }
    }

        public static class E2EEException extends Exception {

        public E2EEException(String message) {
            super(message);
        }

        public E2EEException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
