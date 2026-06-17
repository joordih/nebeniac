package dev.neuralabs.loader.crypto.e2ee;

import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TinkE2EEClient {

    private static final String PUBLIC_KEY_RESOURCE = "/server_public_key.json";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final Logger logger;
    private final Gson gson;
    private KeysetHandle publicKeysetHandle;
    private HybridEncrypt hybridEncrypt;
    private boolean initialized = false;

        public TinkE2EEClient(Logger logger) {
        this.logger = logger;
        this.gson = new GsonBuilder().setPrettyPrinting().create();

        try {
           
            HybridConfig.register();
            logger.info("Google Tink HybridConfig registered successfully");

           
            loadPublicKey();

            this.initialized = true;
            logger.info("TinkE2EEClient initialized successfully");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to initialize TinkE2EEClient", e);
        }
    }

        private void loadPublicKey() throws GeneralSecurityException, Exception {
        try (InputStream is = getClass().getResourceAsStream(PUBLIC_KEY_RESOURCE)) {
            if (is == null) {
                throw new Exception("Public key resource not found: " + PUBLIC_KEY_RESOURCE);
            }

           
            byte[] keyBytes = readAllBytes(is);
            String publicKeyJson = new String(keyBytes, StandardCharsets.UTF_8);

           
            publicKeysetHandle = KeysetHandle.readNoSecret(
                JsonKeysetReader.withString(publicKeyJson)
            );

           
            hybridEncrypt = publicKeysetHandle.getPrimitive(HybridEncrypt.class);

            logger.info("Server public key loaded successfully");
        }
    }

        public String encryptPayload(String plaintext) throws GeneralSecurityException {
        if (!initialized) {
            throw new IllegalStateException("TinkE2EEClient is not initialized");
        }

       
        String nonce = generateNonce();
        long timestamp = System.currentTimeMillis();

       
        Map<String, Object> innerPayload = new HashMap<>();
        innerPayload.put("data", plaintext);
        innerPayload.put("nonce", nonce);
        innerPayload.put("timestamp", timestamp);

        String innerJson = gson.toJson(innerPayload);

       
        byte[] ciphertext = hybridEncrypt.encrypt(
            innerJson.getBytes(StandardCharsets.UTF_8),
            new byte[0]
        );

       
        Map<String, Object> envelope = new HashMap<>();
        envelope.put("ciphertext", Base64.getEncoder().encodeToString(ciphertext));
        envelope.put("timestamp", timestamp);
        envelope.put("version", "1.0");

        return gson.toJson(envelope);
    }

        public String encryptPayload(Map<String, Object> dataMap) throws GeneralSecurityException {
        String plaintext = gson.toJson(dataMap);
        return encryptPayload(plaintext);
    }

        public String encryptBytes(byte[] plaintext, byte[] contextInfo) throws GeneralSecurityException {
        if (!initialized) {
            throw new IllegalStateException("TinkE2EEClient is not initialized");
        }

        byte[] ciphertext = hybridEncrypt.encrypt(plaintext, contextInfo);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

        public String encryptBytes(byte[] plaintext) throws GeneralSecurityException {
        return encryptBytes(plaintext, new byte[0]);
    }

        private String generateNonce() {
        byte[] nonceBytes = new byte[16];
        SECURE_RANDOM.nextBytes(nonceBytes);
        return Base64.getEncoder().encodeToString(nonceBytes);
    }

        public boolean isInitialized() {
        return initialized && hybridEncrypt != null;
    }

        private byte[] readAllBytes(InputStream is) throws Exception {
        byte[] buffer = new byte[8192];
        int bytesRead;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();

        while ((bytesRead = is.read(buffer)) != -1) {
            output.write(buffer, 0, bytesRead);
        }

        return output.toByteArray();
    }

        public Gson getGson() {
        return gson;
    }
}
