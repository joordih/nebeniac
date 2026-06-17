package dev.neuralabs.auth.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.AesGcmJce;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class E2EEResponseEncryption {

    private static final String ENCRYPTION_VERSION = "1.0";
    private static final int SESSION_KEY_CACHE_MAX_SIZE = 10000;

    private final TinkE2EEManager hybridManager;
    private final ObjectMapper objectMapper;
    private final Map<String, Aead> sessionCipherCache;
    private final boolean responseEncryptionEnabled;

        public E2EEResponseEncryption(boolean enabled)
        throws GeneralSecurityException, IOException {
        this.responseEncryptionEnabled = enabled;
        this.objectMapper = new ObjectMapper();
        this.sessionCipherCache = new ConcurrentHashMap<>();

        if (enabled) {
           
            AeadConfig.register();

           
            this.hybridManager = new TinkE2EEManager();

            log.info(
                "E2EE Response Encryption Service initialized (enabled: {})",
                enabled
            );
        } else {
            this.hybridManager = null;
            log.info("E2EE Response Encryption Service disabled");
        }
    }

        public String encryptResponse(Object responseData, String sessionToken)
        throws E2EEEncryptionException {
        if (!responseEncryptionEnabled) {
            throw new E2EEEncryptionException(
                "Response encryption is disabled"
            );
        }

        try {
           
            String plaintext = objectMapper.writeValueAsString(responseData);

           
            Aead aead = getOrCreateSessionCipher(sessionToken);

            byte[] associatedData = sessionToken.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = aead.encrypt(
                plaintext.getBytes(StandardCharsets.UTF_8),
                associatedData
            );

           
            Map<String, Object> envelope = new HashMap<>();
            envelope.put("encrypted", true);
            envelope.put(
                "ciphertext",
                Base64.getEncoder().encodeToString(ciphertext)
            );
            envelope.put("timestamp", System.currentTimeMillis());
            envelope.put("version", ENCRYPTION_VERSION);
            envelope.put("encryptionType", "AEAD");

            return objectMapper.writeValueAsString(envelope);
        } catch (GeneralSecurityException e) {
            log.error("Encryption failed: {}", e.getMessage());
            throw new E2EEEncryptionException(
                "Failed to encrypt response: " + e.getMessage(),
                e
            );
        } catch (IOException e) {
            log.error("Failed to serialize response: {}", e.getMessage());
            throw new E2EEEncryptionException(
                "Failed to serialize response: " + e.getMessage(),
                e
            );
        }
    }

        public String encryptResponseHybrid(
        Object responseData,
        String clientPublicKeyJson
    ) throws E2EEEncryptionException {
        if (!responseEncryptionEnabled) {
            throw new E2EEEncryptionException(
                "Response encryption is disabled"
            );
        }

        try {
            String plaintext = objectMapper.writeValueAsString(responseData);

            KeysetHandle clientPublicKey = KeysetHandle.readNoSecret(
                JsonKeysetReader.withString(clientPublicKeyJson)
            );

            HybridEncrypt hybridEncrypt = clientPublicKey.getPrimitive(
                HybridEncrypt.class
            );

            byte[] ciphertext = hybridEncrypt.encrypt(
                plaintext.getBytes(StandardCharsets.UTF_8),
                new byte[0]
            );

            Map<String, Object> envelope = new HashMap<>();
            envelope.put("encrypted", true);
            envelope.put(
                "ciphertext",
                Base64.getEncoder().encodeToString(ciphertext)
            );
            envelope.put("timestamp", System.currentTimeMillis());
            envelope.put("version", ENCRYPTION_VERSION);
            envelope.put("encryptionType", "HYBRID");

            return objectMapper.writeValueAsString(envelope);
        } catch (GeneralSecurityException e) {
            log.error("Hybrid encryption failed: {}", e.getMessage());
            throw new E2EEEncryptionException(
                "Failed to encrypt response: " + e.getMessage(),
                e
            );
        } catch (IOException e) {
            log.error("Failed to serialize response: {}", e.getMessage());
            throw new E2EEEncryptionException(
                "Failed to serialize response: " + e.getMessage(),
                e
            );
        }
    }

        public String encryptResponseAuto(
        Object responseData,
        String sessionToken,
        String clientPublicKey
    ) {
        if (!responseEncryptionEnabled) {
            try {
                return objectMapper.writeValueAsString(responseData);
            } catch (IOException e) {
                log.error("Failed to serialize response", e);
                return "{\"error\":\"Serialization failed\"}";
            }
        }

        try {
           
            if (sessionToken != null && !sessionToken.isEmpty()) {
                return encryptResponse(responseData, sessionToken);
            }

           
            if (clientPublicKey != null && !clientPublicKey.isEmpty()) {
                return encryptResponseHybrid(responseData, clientPublicKey);
            }

           
            log.debug(
                "No encryption method available, returning plaintext response"
            );
            return objectMapper.writeValueAsString(responseData);
        } catch (E2EEEncryptionException e) {
            log.warn(
                "Encryption failed, falling back to plaintext: {}",
                e.getMessage()
            );
            try {
                return objectMapper.writeValueAsString(responseData);
            } catch (IOException ex) {
                log.error("Failed to serialize response", ex);
                return "{\"error\":\"Serialization failed\"}";
            }
        } catch (IOException e) {
            log.error("Failed to serialize response", e);
            return "{\"error\":\"Serialization failed\"}";
        }
    }

        private Aead getOrCreateSessionCipher(String sessionToken)
        throws GeneralSecurityException {
        Aead cached = sessionCipherCache.get(sessionToken);
        if (cached != null) {
            return cached;
        }

        if (sessionCipherCache.size() >= SESSION_KEY_CACHE_MAX_SIZE) {
            log.warn("Session key cache is full, clearing oldest entries");
            sessionCipherCache.clear();
        }

        byte[] key = deriveSessionKey(sessionToken);
        Aead aead = new AesGcmJce(key);
        sessionCipherCache.put(sessionToken, aead);

        log.debug(
            "Generated deterministic session cipher for token: {}",
            sessionToken.substring(0, Math.min(8, sessionToken.length()))
        );

        return aead;
    }

        public void clearSessionKey(String sessionToken) {
        if (sessionCipherCache.remove(sessionToken) != null) {
            log.debug(
                "Cleared session key for token: {}",
                sessionToken.substring(0, Math.min(8, sessionToken.length()))
            );
        }
    }

        public void clearAllSessionKeys() {
        int size = sessionCipherCache.size();
        sessionCipherCache.clear();
        log.info("Cleared {} session keys from cache", size);
    }

        public boolean isEnabled() {
        return responseEncryptionEnabled;
    }

        public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("enabled", responseEncryptionEnabled);
        stats.put("cachedSessionKeys", sessionCipherCache.size());
        stats.put("encryptionVersion", ENCRYPTION_VERSION);
        stats.put("cacheMaxSize", SESSION_KEY_CACHE_MAX_SIZE);
        return stats;
    }

    private byte[] deriveSessionKey(String sessionToken) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(sessionToken.getBytes(StandardCharsets.UTF_8));
    }

        public static class E2EEEncryptionException extends Exception {

        public E2EEEncryptionException(String message) {
            super(message);
        }

        public E2EEEncryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
