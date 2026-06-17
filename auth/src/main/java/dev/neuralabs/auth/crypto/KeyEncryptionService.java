package dev.neuralabs.auth.crypto;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Key Encryption Key (KEK) service for wrapping encryption keys before database storage.
 * SECURITY: Encryption keys are never stored in plaintext in the database.
 * 
 * Architecture:
 * - Master KEK is derived from environment variable or HSM
 * - Each encryption key is wrapped with AES-256-GCM before storage
 * - KEK never leaves the server memory
 * - Supports key rotation
 * 
 * Usage:
 * 1. Initialize with master key from secure source
 * 2. Wrap keys before storing in database
 * 3. Unwrap keys when needed for operations
 * 4. Rotate KEK periodically
 */
@Slf4j
public class KeyEncryptionService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int TAG_LENGTH = 128;
    private static final String KEK_VERSION = "v1";

    private SecretKey masterKEK;
    private final SecureRandom secureRandom;

    public KeyEncryptionService() {
        this.secureRandom = new SecureRandom();
        initializeMasterKEK();
    }

    /**
     * Initializes the master KEK from environment or generates a new one.
     * PRODUCTION: Should load from HSM, KMS, or secure vault.
     */
    private void initializeMasterKEK() {
        try {
            // Try to load from environment variable
            String kekBase64 = System.getenv("NEBENIAC_MASTER_KEK");
            
            if (kekBase64 != null && !kekBase64.isEmpty()) {
                byte[] kekBytes = Base64.getDecoder().decode(kekBase64);
                this.masterKEK = new SecretKeySpec(kekBytes, ALGORITHM);
                log.info("Master KEK loaded from environment");
            } else {
                // Generate new KEK (for development only)
                log.warn("No master KEK found in environment, generating new one");
                log.warn("PRODUCTION WARNING: Master KEK should be loaded from HSM/KMS!");
                this.masterKEK = generateKEK();
                
                // Log the generated KEK for setup (REMOVE IN PRODUCTION)
                String kekForSetup = Base64.getEncoder().encodeToString(masterKEK.getEncoded());
                log.warn("Generated KEK (set as NEBENIAC_MASTER_KEK): {}", kekForSetup);
            }
        } catch (Exception e) {
            log.error("Failed to initialize master KEK", e);
            throw new RuntimeException("Cannot initialize key encryption service", e);
        }
    }

    /**
     * Generates a new KEK.
     */
    private SecretKey generateKEK() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Wraps (encrypts) an encryption key for storage.
     * 
     * @param plaintextKey The key to wrap (Base64 encoded)
     * @return Wrapped key with IV and version (Base64 encoded)
     */
    public String wrapKey(String plaintextKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(plaintextKey);
            
            // Generate random IV
            byte[] iv = new byte[IV_SIZE];
            secureRandom.nextBytes(iv);

            // Encrypt the key
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, masterKEK, gcmSpec);
            
            // Add version as AAD (Additional Authenticated Data)
            cipher.updateAAD(KEK_VERSION.getBytes(StandardCharsets.UTF_8));
            
            byte[] encryptedKey = cipher.doFinal(keyBytes);

            // Combine: version(2) + iv(12) + encrypted(variable)
            ByteBuffer buffer = ByteBuffer.allocate(2 + IV_SIZE + encryptedKey.length);
            buffer.putShort((short) KEK_VERSION.length());
            buffer.put(iv);
            buffer.put(encryptedKey);

            // Clear sensitive data
            Arrays.fill(keyBytes, (byte) 0);

            String wrapped = Base64.getEncoder().encodeToString(buffer.array());
            log.debug("Key wrapped successfully");
            return wrapped;

        } catch (Exception e) {
            log.error("Failed to wrap key", e);
            throw new RuntimeException("Key wrapping failed", e);
        }
    }

    /**
     * Unwraps (decrypts) an encryption key from storage.
     * 
     * @param wrappedKey The wrapped key (Base64 encoded)
     * @return Unwrapped key (Base64 encoded)
     */
    public String unwrapKey(String wrappedKey) {
        try {
            byte[] wrappedBytes = Base64.getDecoder().decode(wrappedKey);
            ByteBuffer buffer = ByteBuffer.wrap(wrappedBytes);

            // Extract version length (for future version support)
            short versionLength = buffer.getShort();
            
            // Extract IV
            byte[] iv = new byte[IV_SIZE];
            buffer.get(iv);

            // Extract encrypted key
            byte[] encryptedKey = new byte[buffer.remaining()];
            buffer.get(encryptedKey);

            // Decrypt the key
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterKEK, gcmSpec);
            
            // Add version as AAD
            cipher.updateAAD(KEK_VERSION.getBytes(StandardCharsets.UTF_8));
            
            byte[] decryptedKey = cipher.doFinal(encryptedKey);

            String unwrapped = Base64.getEncoder().encodeToString(decryptedKey);
            
            // Clear sensitive data
            Arrays.fill(decryptedKey, (byte) 0);
            
            log.debug("Key unwrapped successfully");
            return unwrapped;

        } catch (Exception e) {
            log.error("Failed to unwrap key", e);
            throw new RuntimeException("Key unwrapping failed - possible tampering or wrong KEK", e);
        }
    }

    /**
     * Rotates the master KEK and re-wraps all keys.
     * 
     * @param oldWrappedKeys List of keys wrapped with old KEK
     * @param newKEK The new KEK to use
     * @return List of keys wrapped with new KEK
     */
    public java.util.List<String> rotateKEK(java.util.List<String> oldWrappedKeys, SecretKey newKEK) {
        log.info("Starting KEK rotation for {} keys", oldWrappedKeys.size());
        
        java.util.List<String> newWrappedKeys = new java.util.ArrayList<>();
        SecretKey oldKEK = this.masterKEK;

        try {
            for (String oldWrapped : oldWrappedKeys) {
                // Unwrap with old KEK
                this.masterKEK = oldKEK;
                String plaintext = unwrapKey(oldWrapped);

                // Wrap with new KEK
                this.masterKEK = newKEK;
                String newWrapped = wrapKey(plaintext);

                newWrappedKeys.add(newWrapped);
            }

            // Update to new KEK
            this.masterKEK = newKEK;
            log.info("KEK rotation completed successfully");

            return newWrappedKeys;

        } catch (Exception e) {
            // Rollback on error
            this.masterKEK = oldKEK;
            log.error("KEK rotation failed, rolled back to old KEK", e);
            throw new RuntimeException("KEK rotation failed", e);
        }
    }

    /**
     * Validates that a wrapped key can be unwrapped (integrity check).
     */
    public boolean validateWrappedKey(String wrappedKey) {
        try {
            unwrapKey(wrappedKey);
            return true;
        } catch (Exception e) {
            log.warn("Wrapped key validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Gets the current KEK version.
     */
    public String getKEKVersion() {
        return KEK_VERSION;
    }

    /**
     * Securely destroys the KEK from memory (best effort).
     */
    public void destroy() {
        if (masterKEK != null) {
            try {
                byte[] encoded = masterKEK.getEncoded();
                Arrays.fill(encoded, (byte) 0);
            } catch (Exception e) {
                log.warn("Could not securely destroy KEK", e);
            }
        }
        log.info("KeyEncryptionService destroyed");
    }

    /**
     * Generates a setup command for production deployment.
     */
    public static String generateSetupCommand() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE, new SecureRandom());
        SecretKey kek = keyGen.generateKey();
        String kekBase64 = Base64.getEncoder().encodeToString(kek.getEncoded());
        
        return "export NEBENIAC_MASTER_KEK=\"" + kekBase64 + "\"";
    }

    /**
     * Main method for generating a new KEK for production setup.
     */
    public static void main(String[] args) throws Exception {
        log.info("=== Nebeniac Key Encryption Key Generator ===");
        log.info("Add this to your environment variables: {}", generateSetupCommand());
        log.info("IMPORTANT: Store this KEK securely! Use HSM/KMS in production, never commit to VCS, rotate periodically, backup securely.");
    }
}
