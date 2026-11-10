package dev.neuralabs.loader.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.logging.Logger;

public class NebeniacCryptoProvider {
  private static final String ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int TAG_LENGTH = 128;

  private final Logger logger;
  private final String encryptionKeyBase64;

  public NebeniacCryptoProvider(String encryptionKeyBase64, Logger logger) {
    this.encryptionKeyBase64 = encryptionKeyBase64;
    this.logger = logger;
  }

  private byte[] decodeKey() {
    try {
      return Base64.getDecoder().decode(encryptionKeyBase64);
    } catch (Exception e) {
      logger.warning("Error decodificando clave de cifrado: " + e.getMessage());
      return null;
    }
  }

  private byte[] decrypt(byte[] data, byte[] key, byte[] iv) throws CryptoException {
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
      byte[] key = decodeKey();
      if (key == null) {
        throw new CryptoException("Could not generate encryption key");
      }
      return decrypt(encryptedData, key, iv);
    } catch (Exception e) {
      throw new CryptoException("Error descifrando con formato Nebeniac: " + e.getMessage(), e);
    }
  }
}
