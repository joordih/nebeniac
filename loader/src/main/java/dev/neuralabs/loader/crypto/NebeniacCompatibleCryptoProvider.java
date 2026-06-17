package dev.neuralabs.loader.crypto;

import lombok.Getter;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

@Getter
public class NebeniacCompatibleCryptoProvider implements CryptoProvider {

  private static final String ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int KEY_SIZE = 256;
  private static final int IV_SIZE = 12;
  private static final int TAG_LENGTH = 128;

  private final SecureRandom secureRandom;

  public NebeniacCompatibleCryptoProvider() {
    this.secureRandom = new SecureRandom();
  }

  @Override
  public String getAlgorithmName() {
    return "AES-256-GCM-Nebeniac";
  }

  @Override
  @Deprecated
  public byte[] generateKey(String seed, String context) {
    // DEPRECATED: This method uses weak SHA-256 KDF without salt.
    // This compatibility mode should not be used in production.
    // Use NebeniacCryptoProvider with proper HKDF instead.
    throw new UnsupportedOperationException(
      "NebeniacCompatibleCryptoProvider is deprecated due to weak KDF. Use NebeniacCryptoProvider instead."
    );
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

  public byte[] decryptWithNebeniacCompatibility(byte[] encryptedData, byte[] iv, String className) {
    try {
      String keySeed = "nebeniac-key-" + className;
      byte[] key = generateKey(keySeed, className);
      return decrypt(encryptedData, key, iv);
    } catch (Exception e) {
      throw new RuntimeException("Error descifrando con compatibilidad Nebeniac: " + e.getMessage(), e);
    }
  }

  @Override
  public byte[] generateIV() {
    byte[] iv = new byte[IV_SIZE];
    secureRandom.nextBytes(iv);
    return iv;
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
