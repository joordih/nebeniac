package dev.neuralabs.auth.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class E2EEDecryptionService {
    private static final long MAX_TIMESTAMP_DIFF_MS = 5 * 60 * 1000;
    private static final long NONCE_EXPIRY_MS = 10 * 60 * 1000;
    private static final int NONCE_CLEANUP_INTERVAL_MINUTES = 5;

    private final TinkE2EEManager tinkManager;
    private final ObjectMapper objectMapper;
    private final Map<String, Long> usedNonces;
    private final ScheduledExecutorService cleanupExecutor;

    public E2EEDecryptionService()
        throws GeneralSecurityException, IOException {
        this.tinkManager = new TinkE2EEManager();
        this.objectMapper = new ObjectMapper();
        this.usedNonces = new ConcurrentHashMap<>();
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor();

        scheduleNonceCleanup();

        log.info("E2EE Decryption Service initialized successfully");
    }

    public DecryptedPayload decryptRequest(String encryptedBody)
        throws E2EEException {
        try {
            EncryptedPayload envelope = objectMapper.readValue(
                encryptedBody,
                EncryptedPayload.class
            );

            if (!envelope.isValid()) {
                throw new E2EEException("Invalid encrypted payload structure");
            }

            if (!tinkManager.validateTimestamp(envelope.getTimestamp())) {
                throw new E2EEException(
                    "Envelope timestamp validation failed - possible replay attack"
                );
            }

            String decryptedJson = tinkManager.decrypt(
                envelope.getCiphertext()
            );

            DecryptedPayload payload = objectMapper.readValue(
                decryptedJson,
                DecryptedPayload.class
            );

            if (!payload.isValid()) {
                throw new E2EEException("Invalid decrypted payload structure");
            }

            if (!payload.isTimestampValid(MAX_TIMESTAMP_DIFF_MS)) {
                log.warn(
                    "Inner payload timestamp validation failed. Timestamp: {}, Current: {}",
                    payload.getTimestamp(),
                    System.currentTimeMillis()
                );
                throw new E2EEException(
                    "Payload timestamp validation failed - possible replay attack"
                );
            }

            if (
                !validateAndTrackNonce(
                    payload.getNonce(),
                    payload.getTimestamp()
                )
            ) {
                throw new E2EEException(
                    "Nonce validation failed - possible replay attack"
                );
            }

            log.debug(
                "Successfully decrypted and validated E2EE payload with nonce: {}",
                payload.getNonce()
            );
            return payload;
        } catch (GeneralSecurityException e) {
            log.error("Decryption failed: {}", e.getMessage());
            throw new E2EEException(
                "Failed to decrypt payload: " + e.getMessage(),
                e
            );
        } catch (IOException e) {
            log.error("Failed to parse encrypted payload: {}", e.getMessage());
            throw new E2EEException(
                "Failed to parse encrypted payload: " + e.getMessage(),
                e
            );
        }
    }

    private boolean validateAndTrackNonce(String nonce, Long timestamp) {
        if (nonce == null || nonce.isEmpty()) {
            log.warn("Empty or null nonce received");
            return false;
        }

        if (usedNonces.containsKey(nonce)) {
            log.warn("Replay attack detected! Nonce already used: {}", nonce);
            return false;
        }

        usedNonces.put(
            nonce,
            timestamp != null ? timestamp : System.currentTimeMillis()
        );
        return true;
    }

    private void scheduleNonceCleanup() {
        cleanupExecutor.scheduleAtFixedRate(
            this::cleanupExpiredNonces,
            NONCE_CLEANUP_INTERVAL_MINUTES,
            NONCE_CLEANUP_INTERVAL_MINUTES,
            TimeUnit.MINUTES
        );
        log.info(
            "Scheduled nonce cleanup every {} minutes",
            NONCE_CLEANUP_INTERVAL_MINUTES
        );
    }

    private void cleanupExpiredNonces() {
        long currentTime = System.currentTimeMillis();
        int removedCount = 0;

        Set<String> noncesToRemove = new HashSet<>();
        for (Map.Entry<String, Long> entry : usedNonces.entrySet()) {
            if (currentTime - entry.getValue() > NONCE_EXPIRY_MS) {
                noncesToRemove.add(entry.getKey());
            }
        }

        for (String nonce : noncesToRemove) {
            usedNonces.remove(nonce);
            removedCount++;
        }

        if (removedCount > 0) {
            log.debug(
                "Cleaned up {} expired nonces. Remaining: {}",
                removedCount,
                usedNonces.size()
            );
        }
    }

    public String getPublicKeyJson() throws IOException {
        return tinkManager.getPublicKeyJson();
    }

    public String getPublicKeyFilePath() {
        return tinkManager.getPublicKeyFilePath();
    }

    public boolean isReady() {
        return tinkManager != null && tinkManager.isInitialized();
    }

    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        log.info("E2EE Decryption Service shutdown complete");
    }

    public Map<String, Object> getStats() {
        return Map.of(
            "trackedNonces",
            usedNonces.size(),
            "isReady",
            isReady(),
            "maxTimestampDiffMs",
            MAX_TIMESTAMP_DIFF_MS,
            "nonceExpiryMs",
            NONCE_EXPIRY_MS
        );
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
