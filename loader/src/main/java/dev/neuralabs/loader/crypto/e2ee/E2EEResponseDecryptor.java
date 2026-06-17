package dev.neuralabs.loader.crypto.e2ee;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class E2EEResponseDecryptor {

    private final Logger logger;
    private final Gson gson;
    private final Map<String, Aead> sessionCiphers;
    private KeysetHandle clientPrivateKey;
    private boolean initialized = false;

        public E2EEResponseDecryptor(Logger logger) {
        this.logger = logger;
        this.gson = new Gson();
        this.sessionCiphers = new ConcurrentHashMap<>();

        try {
           
            AeadConfig.register();
            this.initialized = true;
            logger.info("E2EE Response Decryptor initialized");
        } catch (GeneralSecurityException e) {
            logger.severe("Failed to initialize Response Decryptor: " + e.getMessage());
        }
    }

        public boolean isEncryptedResponse(String responseBody) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            return false;
        }

        try {
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            return json.has("encrypted") &&
                   json.get("encrypted").getAsBoolean() &&
                   json.has("ciphertext");
        } catch (Exception e) {
            return false;
        }
    }

        public String decryptResponse(String encryptedResponse, String sessionToken)
            throws DecryptionException {

        if (!initialized) {
            throw new DecryptionException("Response decryptor not initialized");
        }

       
        if (!isEncryptedResponse(encryptedResponse)) {
           
            return encryptedResponse;
        }

        try {
           
            JsonObject envelope = JsonParser.parseString(encryptedResponse).getAsJsonObject();

            String ciphertextBase64 = envelope.get("ciphertext").getAsString();
            String encryptionType = envelope.has("encryptionType")
                ? envelope.get("encryptionType").getAsString()
                : "AEAD";

            byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);

           
            byte[] plaintext;
            if ("AEAD".equals(encryptionType)) {
                plaintext = decryptWithAEAD(ciphertext, sessionToken);
            } else if ("HYBRID".equals(encryptionType)) {
                plaintext = decryptWithHybrid(ciphertext);
            } else {
                throw new DecryptionException("Unknown encryption type: " + encryptionType);
            }

            String decryptedJson = new String(plaintext, StandardCharsets.UTF_8);
            logger.fine("Successfully decrypted server response");

            return decryptedJson;

        } catch (GeneralSecurityException e) {
            logger.warning("Failed to decrypt response: " + e.getMessage());
            throw new DecryptionException("Decryption failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logger.warning("Failed to parse encrypted response: " + e.getMessage());
            throw new DecryptionException("Failed to parse response: " + e.getMessage(), e);
        }
    }

        private byte[] decryptWithAEAD(byte[] ciphertext, String sessionToken)
            throws GeneralSecurityException {

        if (sessionToken == null || sessionToken.isEmpty()) {
            throw new GeneralSecurityException("Session token required for AEAD decryption");
        }

       
        Aead aead = getOrCreateSessionCipher(sessionToken);

       
        byte[] associatedData = sessionToken.getBytes(StandardCharsets.UTF_8);
        return aead.decrypt(ciphertext, associatedData);
    }

        private byte[] decryptWithHybrid(byte[] ciphertext) throws GeneralSecurityException {
        if (clientPrivateKey == null) {
            throw new GeneralSecurityException("Client private key not loaded for hybrid decryption");
        }

        HybridDecrypt hybridDecrypt = clientPrivateKey.getPrimitive(HybridDecrypt.class);
        return hybridDecrypt.decrypt(ciphertext, new byte[0]);
    }

        private Aead getOrCreateSessionCipher(String sessionToken)
            throws GeneralSecurityException {

        Aead cached = sessionCiphers.get(sessionToken);
        if (cached != null) {
            return cached;
        }

        byte[] key = deriveSessionKey(sessionToken);
        Aead aead = new AesGcmJce(key);
        sessionCiphers.put(sessionToken, aead);

        logger.fine("Derived session cipher for token: " +
            sessionToken.substring(0, Math.min(8, sessionToken.length())));

        return aead;
    }

    private byte[] deriveSessionKey(String sessionToken) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(sessionToken.getBytes(StandardCharsets.UTF_8));
    }

        public void loadClientPrivateKey(String privateKeyJson) throws GeneralSecurityException {
        try {
            this.clientPrivateKey = KeysetHandle.readNoSecret(
                JsonKeysetReader.withString(privateKeyJson)
            );
            logger.info("Client private key loaded for hybrid decryption");
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to load private key: " + e.getMessage(), e);
        }
    }

        public void clearSessionKey(String sessionToken) {
        if (sessionCiphers.remove(sessionToken) != null) {
            logger.fine("Cleared session key for token: " +
                sessionToken.substring(0, Math.min(8, sessionToken.length())));
        }
    }

        public void clearAllSessionKeys() {
        int count = sessionCiphers.size();
        sessionCiphers.clear();
        logger.info("Cleared " + count + " session keys");
    }

        public boolean isInitialized() {
        return initialized;
    }

        public static class DecryptionException extends Exception {
        public DecryptionException(String message) {
            super(message);
        }

        public DecryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
