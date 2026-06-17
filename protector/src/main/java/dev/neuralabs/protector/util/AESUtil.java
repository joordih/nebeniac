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


    public void clear() {
      Arrays.fill(encryptedBytes, (byte) 0);
      Arrays.fill(iv, (byte) 0);
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


  public static byte[] decrypt(EncryptedData encryptedData, SecretKey key) throws Exception {

    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, encryptedData.getIv());

    cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);


    byte[] plaintext = cipher.doFinal(encryptedData.getEncryptedBytes());

    logger.debug("Successfully decrypted {} bytes", plaintext.length);

    return plaintext;
  }


  public static EncryptedData encryptString(String plaintext, SecretKey key) throws Exception {
    return encrypt(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8), key);
  }


  public static String decryptString(EncryptedData encryptedData, SecretKey key) throws Exception {
    byte[] plaintext = decrypt(encryptedData, key);
    try {
      return new String(plaintext, java.nio.charset.StandardCharsets.UTF_8);
    } finally {

      Arrays.fill(plaintext, (byte) 0);
    }
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


  public static void clearKey(SecretKey key) {
    if (key != null) {
      Arrays.fill(key.getEncoded(), (byte) 0);
    }
  }


  public static boolean isValidKeyLength(SecretKey key) {
    return key != null && key.getEncoded().length == KEY_LENGTH;
  }


  public static boolean testEncryption() {
    try {

      String testData = "Test encryption data - 测试加密数据 - Données de test de chiffrement";
      SecretKey key = generateKey();


      EncryptedData encrypted = encryptString(testData, key);


      String decrypted = decryptString(encrypted, key);


      boolean success = testData.equals(decrypted);


      clearKey(key);
      encrypted.clear();

      if (success) {
        logger.debug("Encryption test passed");
      } else {
        logger.error("Encryption test failed");
      }

      return success;

    } catch (Exception e) {
      logger.error("Encryption test failed with exception", e);
      return false;
    }
  }
}
