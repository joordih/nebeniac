package dev.neuralabs.loader.crypto;

import lombok.Getter;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

@Getter
public class AESCryptoProvider implements CryptoProvider {

  private static final String ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int KEY_SIZE = 256;
  private static final int IV_SIZE = 12;
  private static final int TAG_LENGTH = 128;

  private final SecureRandom secureRandom;

  public AESCryptoProvider() {
    this.secureRandom = new SecureRandom();
  }

  @Override
  public String getAlgorithmName() {
    return "AES-256-GCM";
  }

  @Override
  @Deprecated
  public byte[] generateKey(String seed, String context) {
    // DEPRECATED: This method uses weak SHA-256 KDF without salt.
    // This provider should not be used in production.
    // Use NebeniacCryptoProvider with proper HKDF instead.
    throw new UnsupportedOperationException(
      "AESCryptoProvider is deprecated due to weak KDF. Use NebeniacCryptoProvider instead."
    );
  }

  /**
   * Secure key derivation using HKDF (HMAC-based KDF).
   * This should be used instead of the deprecated generateKey method.
   */
  public byte[] generateKeyHKDF(String seed, String context, byte[] salt) {
    try {
      byte[] ikm = (seed + ":" + context).getBytes(StandardCharsets.UTF_8);
      byte[] info = "AES-256-GCM".getBytes(StandardCharsets.UTF_8);
      
      // HKDF-Extract
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(salt, "HmacSHA256"));
      byte[] prk = mac.doFinal(ikm);
      
      // HKDF-Expand
      mac.reset();
      mac.init(new SecretKeySpec(prk, "HmacSHA256"));
      mac.update(info);
      mac.update((byte) 1);
      byte[] okm = mac.doFinal();
      
      // Clear sensitive data
      Arrays.fill(ikm, (byte) 0);
      Arrays.fill(prk, (byte) 0);
      
      return okm;
    } catch (Exception e) {
      throw new RuntimeException("Error generando clave con HKDF: " + e.getMessage(), e);
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
