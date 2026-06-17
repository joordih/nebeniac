package dev.neuralabs.loader.crypto;

import lombok.Getter;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.logging.Logger;

@Getter
public class NebeniacCryptoProvider implements CryptoProvider {

  private static final String ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int KEY_SIZE = 256;
  private static final int IV_SIZE = 12;
  private static final int TAG_LENGTH = 128;

  private final Logger logger;
  private final String encryptionKeyBase64;

  public NebeniacCryptoProvider(String encryptionKeyBase64, Logger logger) {
    this.encryptionKeyBase64 = encryptionKeyBase64;
    this.logger = logger;
  }

  @Override
  public String getAlgorithmName() {
    return "AES-256-GCM-Nebeniac";
  }

  @Override
  public byte[] generateKey(String seed, String context) {
    try {
      byte[] keyBytes = Base64.getDecoder().decode(encryptionKeyBase64);
      return keyBytes;
    } catch (Exception e) {
      logger.warning("Error decodificando clave de cifrado: " + e.getMessage());
      return null;
    }
  }

  @Override
  public byte[] encrypt(byte[] data, byte[] key, byte[] iv) throws CryptoException {
    try {
      SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

      return cipher.doFinal(data);
    } catch (Exception e) {
      throw new CryptoException("Error cifrando datos: " + e.getMessage(), e);
    }
  }

  @Override
  public byte[] decrypt(byte[] data, byte[] key, byte[] iv) throws CryptoException {
    try {
      SecretKeySpec secretKey = new SecretKeySpec(key, ALGORITHM);
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH, iv);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

      return cipher.doFinal(data);
    } catch (Exception e) {
      throw new CryptoException("Error descifrando datos: " + e.getMessage(), e);
    }
  }

  public byte[] decryptWithNebeniacFormat(byte[] encryptedData, byte[] iv) throws CryptoException {
    try {
      byte[] key = generateKey("", "");
      if (key == null) {
        throw new CryptoException("Could not generate encryption key");
      }
      return decrypt(encryptedData, key, iv);
    } catch (Exception e) {
      throw new CryptoException("Error descifrando con formato Nebeniac: " + e.getMessage(), e);
    }
  }

  @Override
  public byte[] generateIV() {
    try {
      byte[] iv = new byte[IV_SIZE];
      java.security.SecureRandom.getInstanceStrong().nextBytes(iv);
      return iv;
    } catch (Exception e) {
      logger.warning("SecureRandom.getInstanceStrong() failed, falling back to SecureRandom: " + e.getMessage());
      byte[] iv = new byte[IV_SIZE];
      new java.security.SecureRandom().nextBytes(iv);
      return iv;
    }
  }

  @Override
  public int getKeySize() {
    return KEY_SIZE;
  }

  @Override
  public int getIVSize() {
    return IV_SIZE;
  }
}
