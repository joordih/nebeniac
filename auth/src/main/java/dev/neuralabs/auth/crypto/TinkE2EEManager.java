package dev.neuralabs.auth.crypto;

import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.HybridDecrypt;
import com.google.crypto.tink.HybridEncrypt;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TinkE2EEManager {

    private static final String PRIVATE_KEY_FILE =
        "keys/server_private_key.json";
    private static final String PUBLIC_KEY_FILE = "keys/server_public_key.json";
    private static final long MAX_TIMESTAMP_DIFF_MS = 5 * 60 * 1000;

    private KeysetHandle privateKeysetHandle;
    private KeysetHandle publicKeysetHandle;
    private HybridDecrypt hybridDecrypt;
    private HybridEncrypt hybridEncrypt;

        public TinkE2EEManager() throws GeneralSecurityException, IOException {
       
        HybridConfig.register();
        log.info("Google Tink HybridConfig registered successfully");

       
        String currentDir = System.getProperty("user.dir");
        log.info("Current working directory: {}", currentDir);
        log.info("Keys will be stored in: {}/{}", currentDir, PRIVATE_KEY_FILE);

       
        initializeKeys();
    }

        private void initializeKeys() throws GeneralSecurityException, IOException {
        File privateKeyFile = new File(PRIVATE_KEY_FILE);
        File publicKeyFile = new File(PUBLIC_KEY_FILE);

        log.info("Checking for existing keys...");
        log.info("  Private key path: {}", privateKeyFile.getAbsolutePath());
        log.info("  Public key path: {}", publicKeyFile.getAbsolutePath());

        if (privateKeyFile.exists() && publicKeyFile.exists()) {
           
            log.info("Keys found, loading...");
            loadKeys();
            log.info("✓ Loaded existing E2EE keys from files");
        } else {
           
            if (!privateKeyFile.exists()) {
                log.info(
                    "Private key not found at: {}",
                    privateKeyFile.getAbsolutePath()
                );
            }
            if (!publicKeyFile.exists()) {
                log.info(
                    "Public key not found at: {}",
                    publicKeyFile.getAbsolutePath()
                );
            }
            log.info("Generating new E2EE key pair...");
            generateAndSaveKeys();
            log.info("✓ Generated new E2EE key pair");
        }

       
        this.hybridDecrypt = privateKeysetHandle.getPrimitive(
            HybridDecrypt.class
        );
        this.hybridEncrypt = publicKeysetHandle.getPrimitive(
            HybridEncrypt.class
        );
        log.info("✓ Hybrid decrypt/encrypt primitives initialized");
    }

        @SuppressWarnings("deprecation")
    private void generateAndSaveKeys()
        throws GeneralSecurityException, IOException {
       
        File keysDir = new File("keys");
        log.info("Keys directory: {}", keysDir.getAbsolutePath());

        if (!keysDir.exists()) {
            log.info("Creating keys directory...");
            boolean created = keysDir.mkdirs();
            if (created) {
                log.info("✓ Keys directory created successfully");
            } else {
                log.error("Failed to create keys directory!");
                throw new IOException(
                    "Cannot create keys directory: " + keysDir.getAbsolutePath()
                );
            }
        } else {
            log.info("Keys directory already exists");
        }

       
        if (!keysDir.canWrite()) {
            log.error("Keys directory is not writable!");
            throw new IOException(
                "Keys directory is not writable: " + keysDir.getAbsolutePath()
            );
        }

       
        log.info(
            "Generating key pair using ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM..."
        );
        privateKeysetHandle = KeysetHandle.generateNew(
            HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
        );
        log.info("✓ Private key generated");

       
        publicKeysetHandle = privateKeysetHandle.getPublicKeysetHandle();
        log.info("✓ Public key extracted");

       
        log.info("Saving private key to: {}", PRIVATE_KEY_FILE);
        try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_FILE)) {
            CleartextKeysetHandle.write(
                privateKeysetHandle,
                JsonKeysetWriter.withOutputStream(fos)
            );
        }
        File privateFile = new File(PRIVATE_KEY_FILE);
        log.info("✓ Private key saved ({} bytes)", privateFile.length());

       
        log.info("Saving public key to: {}", PUBLIC_KEY_FILE);
        try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILE)) {
            publicKeysetHandle.writeNoSecret(
                JsonKeysetWriter.withOutputStream(fos)
            );
        }
        File publicFile = new File(PUBLIC_KEY_FILE);
        log.info("✓ Public key saved ({} bytes)", publicFile.length());

        log.info("Keys saved successfully:");
        log.info(
            "  Private: {} ({} bytes)",
            privateFile.getAbsolutePath(),
            privateFile.length()
        );
        log.info(
            "  Public:  {} ({} bytes)",
            publicFile.getAbsolutePath(),
            publicFile.length()
        );
    }

        @SuppressWarnings("deprecation")
    private void loadKeys() throws GeneralSecurityException, IOException {
       
        log.info("Loading private key from: {}", PRIVATE_KEY_FILE);
        String privateKeyJson = new String(
            Files.readAllBytes(Paths.get(PRIVATE_KEY_FILE)),
            StandardCharsets.UTF_8
        );
        privateKeysetHandle = CleartextKeysetHandle.read(
            JsonKeysetReader.withString(privateKeyJson)
        );
        log.info("✓ Private key loaded successfully");

       
        log.info("Loading public key from: {}", PUBLIC_KEY_FILE);
        String publicKeyJson = new String(
            Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE)),
            StandardCharsets.UTF_8
        );
        publicKeysetHandle = KeysetHandle.readNoSecret(
            JsonKeysetReader.withString(publicKeyJson)
        );
        log.info("✓ Public key loaded successfully");
    }

        public String decrypt(String ciphertextBase64, byte[] contextInfo)
        throws GeneralSecurityException {
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
        byte[] plaintext = hybridDecrypt.decrypt(ciphertext, contextInfo);
        return new String(plaintext, StandardCharsets.UTF_8);
    }

        public String decrypt(String ciphertextBase64)
        throws GeneralSecurityException {
        return decrypt(ciphertextBase64, new byte[0]);
    }

        public String encrypt(String plaintext, byte[] contextInfo)
        throws GeneralSecurityException {
        byte[] ciphertext = hybridEncrypt.encrypt(
            plaintext.getBytes(StandardCharsets.UTF_8),
            contextInfo
        );
        return Base64.getEncoder().encodeToString(ciphertext);
    }

        public String encrypt(String plaintext) throws GeneralSecurityException {
        return encrypt(plaintext, new byte[0]);
    }

        public String getPublicKeyJson() throws IOException {
        return new String(
            Files.readAllBytes(Paths.get(PUBLIC_KEY_FILE)),
            StandardCharsets.UTF_8
        );
    }

        public boolean validateTimestamp(long timestamp) {
        long currentTime = System.currentTimeMillis();
        long diff = Math.abs(currentTime - timestamp);

        if (diff > MAX_TIMESTAMP_DIFF_MS) {
            log.warn(
                "Timestamp validation failed. Diff: {} ms, Max allowed: {} ms",
                diff,
                MAX_TIMESTAMP_DIFF_MS
            );
            return false;
        }

        return true;
    }

        public String getPublicKeyFilePath() {
        return PUBLIC_KEY_FILE;
    }

        public boolean isInitialized() {
        return (
            privateKeysetHandle != null &&
            publicKeysetHandle != null &&
            hybridDecrypt != null &&
            hybridEncrypt != null
        );
    }
}
