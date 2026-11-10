package dev.neuralabs.auth.crypto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.crypto.tink.subtle.AesGcmJce;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class E2EEResponseEncryption {
    private static final String ENCRYPTION_VERSION = "2.0";
    private static final int RESPONSE_KEY_BYTES = 32;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public String encryptResponse(Object responseData, DecryptedPayload request)
        throws E2EEEncryptionException {
        byte[] key = null;
        try {
            key = Base64.getDecoder().decode(request.getResponseKey());
            if (key.length != RESPONSE_KEY_BYTES) {
                throw new E2EEEncryptionException("Invalid response key length");
            }

            byte[] plaintext = objectMapper.writeValueAsBytes(responseData);
            byte[] associatedData = request.getNonce().getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext = new AesGcmJce(key).encrypt(plaintext, associatedData);

            return objectMapper.writeValueAsString(Map.of(
                "encrypted", true,
                "ciphertext", Base64.getEncoder().encodeToString(ciphertext),
                "version", ENCRYPTION_VERSION
            ));
        } catch (IllegalArgumentException | GeneralSecurityException | JsonProcessingException e) {
            log.error("Response encryption failed: {}", e.getMessage());
            throw new E2EEEncryptionException("Failed to encrypt response", e);
        } finally {
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
        }
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
