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

public class JarSigner {
    private static final Logger logger = LoggerFactory.getLogger(JarSigner.class);
    private static final String SIGNATURE_ALGORITHM = "Ed25519";
    private static final String SIGNATURE_FILE = "NEBENIAC.SIG";
    private static final String PUBLIC_KEY_FILE = "NEBENIAC.PUB";

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM);
        return keyGen.generateKeyPair();
    }

    public String signJar(File jarFile, PrivateKey privateKey) throws Exception {
        logger.info("Signing JAR: {}", jarFile.getName());

        byte[] jarHash = calculateJarHash(jarFile);

        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(jarHash);
        byte[] signatureBytes = signature.sign();

        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
        logger.info("JAR signed successfully");

        return signatureBase64;
    }

    public boolean verifyJar(File jarFile, String signatureBase64, PublicKey publicKey) {
        try {
            logger.info("Verifying JAR signature: {}", jarFile.getName());

            byte[] jarHash = calculateJarHash(jarFile);

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

    private byte[] calculateJarHash(File jarFile) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (JarFile jar = new JarFile(jarFile)) {
            jar.stream()
                .filter(entry -> !entry.isDirectory())
                .filter(entry -> entry.getName().endsWith(".encrypted") ||
                               entry.getName().endsWith(".iv") ||
                               entry.getName().equals("plugin.yml"))
                .sorted((e1, e2) -> e1.getName().compareTo(e2.getName()))
                .forEach(entry -> {
                    try {
                        digest.update(entry.getName().getBytes(StandardCharsets.UTF_8));

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

    public static String exportPublicKey(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    public static PublicKey importPublicKey(String publicKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBase64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(SIGNATURE_ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    public static String exportPrivateKey(PrivateKey privateKey) {
        byte[] encoded = privateKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }

    public static PrivateKey importPrivateKey(String privateKeyBase64) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBase64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(SIGNATURE_ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    public static void saveKeyPair(KeyPair keyPair, File privateKeyFile, File publicKeyFile) throws Exception {
        String privateKeyPem = exportPrivateKey(keyPair.getPrivate());
        Files.writeString(privateKeyFile.toPath(), privateKeyPem);
        logger.warn("Private key saved to: {} - SECURE THIS FILE!", privateKeyFile.getAbsolutePath());

        String publicKeyPem = exportPublicKey(keyPair.getPublic());
        Files.writeString(publicKeyFile.toPath(), publicKeyPem);
        logger.info("Public key saved to: {}", publicKeyFile.getAbsolutePath());
    }

    public static KeyPair loadKeyPair(File privateKeyFile, File publicKeyFile) throws Exception {
        String privateKeyPem = Files.readString(privateKeyFile.toPath());
        String publicKeyPem = Files.readString(publicKeyFile.toPath());

        PrivateKey privateKey = importPrivateKey(privateKeyPem);
        PublicKey publicKey = importPublicKey(publicKeyPem);

        return new KeyPair(publicKey, privateKey);
    }

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
