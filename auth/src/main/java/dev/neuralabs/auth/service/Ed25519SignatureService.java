package dev.neuralabs.auth.service;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class Ed25519SignatureService {
    private static final String KEYS_DIR = "auth/keys/signatures";
    private static final String PRIVATE_KEY_FILE = "ed25519_private.pem";
    private static final String PUBLIC_KEY_FILE = "ed25519_public.pem";
    private static final String PUBLIC_KEY_BASE64_FILE = "public_key_base64url.txt";

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private String publicKeyBase64Url;

    public Ed25519SignatureService() {
        try {
            ensureKeysDirectory();
            loadOrGenerateKeys();
        } catch (Exception e) {
            log.error("Failed to initialize Ed25519 signature service", e);
            throw new RuntimeException("Failed to initialize signature service", e);
        }
    }

    private void ensureKeysDirectory() throws IOException {
        Path keysPath = Paths.get(KEYS_DIR);
        if (!Files.exists(keysPath)) {
            Files.createDirectories(keysPath);
            log.info("Created signature keys directory: {}", KEYS_DIR);
        }
    }

    private void loadOrGenerateKeys() throws Exception {
        Path privateKeyPath = Paths.get(KEYS_DIR, PRIVATE_KEY_FILE);
        Path publicKeyPath = Paths.get(KEYS_DIR, PUBLIC_KEY_FILE);
        Path publicKeyBase64Path = Paths.get(KEYS_DIR, PUBLIC_KEY_BASE64_FILE);

        if (Files.exists(privateKeyPath) && Files.exists(publicKeyPath)) {
            log.info("Loading existing Ed25519 signature keys from: {}", KEYS_DIR);
            loadKeys(privateKeyPath, publicKeyPath);

            if (Files.exists(publicKeyBase64Path)) {
                publicKeyBase64Url = Files.readString(publicKeyBase64Path).trim();
            } else {
                publicKeyBase64Url = generatePublicKeyBase64Url();
                Files.writeString(publicKeyBase64Path, publicKeyBase64Url);
            }
        } else {
            log.info("Generating new Ed25519 signature key pair...");
            generateKeys();
            saveKeys(privateKeyPath, publicKeyPath, publicKeyBase64Path);
        }

        log.info("Ed25519 signature service initialized successfully");
        log.info("Public key (Base64URL): {}", publicKeyBase64Url);
    }

    private void generateKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
        this.publicKeyBase64Url = generatePublicKeyBase64Url();

        log.info("Generated new Ed25519 key pair");
    }

    private void loadKeys(Path privateKeyPath, Path publicKeyPath) throws Exception {
        String privateKeyPem = Files.readString(privateKeyPath);
        privateKeyPem = privateKeyPem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");

        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPem);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        this.privateKey = keyFactory.generatePrivate(privateKeySpec);

        String publicKeyPem = Files.readString(publicKeyPath);
        publicKeyPem = publicKeyPem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");

        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPem);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        this.publicKey = keyFactory.generatePublic(publicKeySpec);

        log.info("Loaded Ed25519 keys from disk");
    }

    private void saveKeys(Path privateKeyPath, Path publicKeyPath, Path publicKeyBase64Path) throws IOException {
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" +
            Base64.getEncoder().encodeToString(privateKey.getEncoded()) + "\n" +
            "-----END PRIVATE KEY-----\n";
        Files.writeString(privateKeyPath, privateKeyPem);

        String publicKeyPem = "-----BEGIN PUBLIC KEY-----\n" +
            Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n" +
            "-----END PUBLIC KEY-----\n";
        Files.writeString(publicKeyPath, publicKeyPem);

        Files.writeString(publicKeyBase64Path, publicKeyBase64Url);

        log.info("Saved Ed25519 keys to: {}", KEYS_DIR);
        log.info("  - Private key: {}", privateKeyPath);
        log.info("  - Public key: {}", publicKeyPath);
        log.info("  - Public key (Base64URL): {}", publicKeyBase64Path);
    }

    private String generatePublicKeyBase64Url() {
        byte[] publicKeyBytes = publicKey.getEncoded();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeyBytes);
    }

    public byte[] sign(byte[] data) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public String signToBase64Url(byte[] data) throws Exception {
        byte[] signatureBytes = sign(data);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
    }

    public boolean verify(byte[] data, byte[] signatureBytes) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public String getPublicKeyBase64Url() {
        return publicKeyBase64Url;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}
