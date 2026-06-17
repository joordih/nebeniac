package dev.neuralabs.protector.signature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.jar.JarFile;

/**
 * Digital signature generation and verification for protected JARs.
 * SECURITY: Ensures JAR integrity and authenticity using Ed25519 signatures.
 * 
 * Features:
 * - Ed25519 digital signatures (fast and secure)
 * - Signs JAR metadata and encrypted content
 * - Verifies signature before loading
 * - Prevents tampering with encrypted JARs
 */
public class JarSigner {

    private static final Logger logger = LoggerFactory.getLogger(JarSigner.class);
    private static final String SIGNATURE_ALGORITHM = "Ed25519";
    private static final String SIGNATURE_FILE = "NEBENIAC.SIG";
    private static final String PUBLIC_KEY_FILE = "NEBENIAC.PUB";

    /**
     * Generates a new Ed25519 key pair for signing.
     * 
     * @return KeyPair containing private and public keys
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM);
        return keyGen.generateKeyPair();
    }

    /**
     * Signs a protected JAR file.
     * 
     * @param jarFile The JAR file to sign
     * @param privateKey The private key for signing
     * @return Base64-encoded signature
     */
    public String signJar(File jarFile, PrivateKey privateKey) throws Exception {
        logger.info("Signing JAR: {}", jarFile.getName());

        // Calculate hash of all encrypted entries
        byte[] jarHash = calculateJarHash(jarFile);

        // Sign the hash
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(jarHash);
        byte[] signatureBytes = signature.sign();

        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        logger.info("JAR signed successfully");

        return signatureBase64;
    }

    /**
     * Verifies the signature of a protected JAR.
     * 
     * @param jarFile The JAR file to verify
     * @param signatureBase64 The signature to verify
     * @param publicKey The public key for verification
     * @return true if signature is valid
     */
    public boolean verifyJar(File jarFile, String signatureBase64, PublicKey publicKey) {
        try {
            logger.info("Verifying JAR signature: {}", jarFile.getName());

            // Calculate current hash
            byte[] jarHash = calculateJarHash(jarFile);

            // Verify signature
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initVerify(publicKey);
            signature.update(jarHash);

            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            boolean valid = signature.verify(signatureBytes);

            if (valid) {
                logger.info("JAR signature is VALID");
            } else {
                logger.error("JAR signature is INVALID - possible tampering detected!");
            }

            return valid;

        } catch (Exception e) {
            logger.error("Error verifying JAR signature: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Calculates a hash of all encrypted entries in the JAR.
     * This ensures the entire encrypted content is covered by the signature.
     */
    private byte[] calculateJarHash(File jarFile) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (JarFile jar = new JarFile(jarFile)) {
            // Process entries in deterministic order
            jar.stream()
                .filter(entry -> !entry.isDirectory())
                .filter(entry -> entry.getName().endsWith(".encrypted") || 
                               entry.getName().endsWith(".iv") ||
                               entry.getName().equals("plugin.yml") ||
                               entry.getName().equals("nebeniac-protection.properties"))
                .sorted((e1, e2) -> e1.getName().compareTo(e2.getName()))
                .forEach(entry -> {
                    try {
                        // Add entry name to hash
                        digest.update(entry.getName().getBytes(StandardCharsets.UTF_8));
                        
                        // Add entry content to hash
                        try (InputStream is = jar.getInputStream(entry)) {
                            byte[] buffer = new byte[8192];
                            int bytesRead;
                            while ((bytesRead = is.read(buffer)) != -1) {
                                digest.update(buffer, 0, bytesRead);
                            }
                        }
                    } catch (Exception e) {
                        throw new RuntimeException("Error hashing JAR entry: " + entry.getName(), e);
                    }
                });
        }

        return digest.digest();
    }

    /**
     * Exports a public key to Base64 format for distribution.
     */
    public static String exportPublicKey(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    /**
     * Imports a public key from Base64 format.
     */
    public static PublicKey importPublicKey(String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(SIGNATURE_ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Exports a private key to Base64 format (KEEP SECURE!).
     */
    public static String exportPrivateKey(PrivateKey privateKey) {
        byte[] encoded = privateKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    /**
     * Imports a private key from Base64 format.
     */
    public static PrivateKey importPrivateKey(String privateKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(SIGNATURE_ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    /**
     * Saves a key pair to files.
     * WARNING: Private key should be stored securely (HSM, encrypted storage, etc.)
     */
    public static void saveKeyPair(KeyPair keyPair, File privateKeyFile, File publicKeyFile) throws Exception {
        // Save private key (MUST BE SECURED!)
        String privateKeyPem = exportPrivateKey(keyPair.getPrivate());
        Files.writeString(privateKeyFile.toPath(), privateKeyPem);
        logger.warn("Private key saved to: {} - SECURE THIS FILE!", privateKeyFile.getAbsolutePath());

        // Save public key (can be distributed)
        String publicKeyPem = exportPublicKey(keyPair.getPublic());
        Files.writeString(publicKeyFile.toPath(), publicKeyPem);
        logger.info("Public key saved to: {}", publicKeyFile.getAbsolutePath());
    }

    /**
     * Loads a key pair from files.
     */
    public static KeyPair loadKeyPair(File privateKeyFile, File publicKeyFile) throws Exception {
        String privateKeyPem = Files.readString(privateKeyFile.toPath());
        String publicKeyPem = Files.readString(publicKeyFile.toPath());

        PrivateKey privateKey = importPrivateKey(privateKeyPem);
        PublicKey publicKey = importPublicKey(publicKeyPem);

        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Signature metadata class for storing signature information.
     */
    public static class SignatureMetadata {
        private final String signature;
        private final String algorithm;
        private final long timestamp;
        private final String jarHash;

        public SignatureMetadata(String signature, String algorithm, long timestamp, String jarHash) {
            this.signature = signature;
            this.algorithm = algorithm;
            this.timestamp = timestamp;
            this.jarHash = jarHash;
        }

        public String getSignature() {
            return signature;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public long getTimestamp() {
            return timestamp;
        }

        public String getJarHash() {
            return jarHash;
        }

        public String toJson() {
            return String.format(
                "{\"signature\":\"%s\",\"algorithm\":\"%s\",\"timestamp\":%d,\"jarHash\":\"%s\"}",
                signature, algorithm, timestamp, jarHash
            );
        }
    }
}
