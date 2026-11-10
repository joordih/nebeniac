package dev.neuralabs.protector.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESUtil {
  private static final Logger logger = LoggerFactory.getLogger(AESUtil.class);

  private static final String ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int GCM_IV_LENGTH = 12;
  private static final int GCM_TAG_LENGTH = 16;
  private static final int KEY_LENGTH = 32;

  public static class EncryptedData {
    private final byte[] encryptedBytes;
    private final byte[] iv;

    public EncryptedData(byte[] encryptedBytes, byte[] iv) {
      this.encryptedBytes = Arrays.copyOf(encryptedBytes, encryptedBytes.length);
      this.iv = Arrays.copyOf(iv, iv.length);
    }

    public byte[] getEncryptedBytes() {
      return Arrays.copyOf(encryptedBytes, encryptedBytes.length);
    }

    public byte[] getIv() {
      return Arrays.copyOf(iv, iv.length);
    }
  }

  public static EncryptedData encrypt(byte[] plaintext, SecretKey key) throws Exception {
    byte[] iv = new byte[GCM_IV_LENGTH];
    SecureRandom.getInstanceStrong().nextBytes(iv);

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

    cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

    byte[] ciphertextWithTag = cipher.doFinal(plaintext);

    logger.debug("Successfully encrypted {} bytes", plaintext.length);

    return new EncryptedData(ciphertextWithTag, iv);
  }

  public static SecretKey generateKey() {
    try {
      KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
      keyGen.init(KEY_LENGTH * 8);
      return keyGen.generateKey();
    } catch (Exception e) {
      logger.error("Key generation failed", e);
      throw new RuntimeException("Key generation failed", e);
    }
  }
}
