package dev.neuralabs.auth.crypto;

import dev.neuralabs.auth.security.SecretStore;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

@Slf4j
public class KeyEncryptionService {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int TAG_LENGTH = 128;
    private static final String KEK_VERSION = "v1";

    private final SecretKey masterKEK;
    private final SecureRandom secureRandom;

    public KeyEncryptionService() {
        this.secureRandom = new SecureRandom();
        this.masterKEK = loadMasterKEK();
    }

    private static SecretKey loadMasterKEK() {
        byte[] kekBytes;
        try {
            kekBytes = Base64.getDecoder().decode(SecretStore.loadOrCreate("NEBENIAC_MASTER_KEK", "master_kek", KEY_SIZE / 8));
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("NEBENIAC_MASTER_KEK must be Base64", e);
        }
        if (kekBytes.length != KEY_SIZE / 8) {
            throw new IllegalStateException("NEBENIAC_MASTER_KEK must decode to " + (KEY_SIZE / 8) + " bytes");
        }
        SecretKey kek = new SecretKeySpec(kekBytes, ALGORITHM);
        Arrays.fill(kekBytes, (byte) 0);
        log.info("Master KEK initialized");
        return kek;
    }

    public String wrapKey(String plaintextKey) {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(plaintextKey);

            byte[] iv = new byte[IV_SIZE];
            secureRandom.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, masterKEK, gcmSpec);

            cipher.updateAAD(KEK_VERSION.getBytes(StandardCharsets.UTF_8));

            byte[] encryptedKey = cipher.doFinal(keyBytes);

            ByteBuffer buffer = ByteBuffer.allocate(2 + IV_SIZE + encryptedKey.length);
            buffer.putShort((short) KEK_VERSION.length());
            buffer.put(iv);
            buffer.put(encryptedKey);

            Arrays.fill(keyBytes, (byte) 0);

            String wrapped = Base64.getEncoder().encodeToString(buffer.array());
            log.debug("Key wrapped successfully");
            return wrapped;
        } catch (Exception e) {
            log.error("Failed to wrap key", e);
            throw new RuntimeException("Key wrapping failed", e);
        }
    }

    public String wrapKeyIfPresent(String plaintextKey) {
        if (plaintextKey == null || plaintextKey.isEmpty()) {
            return null;
        }
        return wrapKey(plaintextKey);
    }

    public String unwrapKey(String wrappedKey) {
        try {
            byte[] wrappedBytes = Base64.getDecoder().decode(wrappedKey);
            ByteBuffer buffer = ByteBuffer.wrap(wrappedBytes);

            buffer.getShort();

            byte[] iv = new byte[IV_SIZE];
            buffer.get(iv);

            byte[] encryptedKey = new byte[buffer.remaining()];
            buffer.get(encryptedKey);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
            cipher.init(Cipher.DECRYPT_MODE, masterKEK, gcmSpec);

            cipher.updateAAD(KEK_VERSION.getBytes(StandardCharsets.UTF_8));

            byte[] decryptedKey = cipher.doFinal(encryptedKey);

            String unwrapped = Base64.getEncoder().encodeToString(decryptedKey);

            Arrays.fill(decryptedKey, (byte) 0);

            log.debug("Key unwrapped successfully");
            return unwrapped;
        } catch (Exception e) {
            log.error("Failed to unwrap key", e);
            throw new RuntimeException("Key unwrapping failed - possible tampering or wrong KEK", e);
        }
    }
}
