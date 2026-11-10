package dev.neuralabs.protector;

import dev.neuralabs.protector.util.AESUtil;
import dev.neuralabs.protector.util.AESUtil.EncryptedData;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionUtil {
  private final SecretKey encryptionKey;

  public EncryptionUtil() throws NoSuchAlgorithmException {
    String providedKey = System.getenv("NEBENIAC_CONTENT_KEY");
    this.encryptionKey = providedKey != null && !providedKey.isBlank()
        ? decodeKey(providedKey.trim())
        : AESUtil.generateKey();
  }

  private static SecretKey decodeKey(String base64Key) {
    byte[] keyBytes = Base64.getDecoder().decode(base64Key);
    if (keyBytes.length != 32) {
      throw new IllegalArgumentException("NEBENIAC_CONTENT_KEY must decode to 32 bytes");
    }
    return new SecretKeySpec(keyBytes, "AES");
  }

  public EncryptedData encryptClass(byte[] classBytes) throws Exception {
    return AESUtil.encrypt(classBytes, encryptionKey);
  }

  public SecretKey getEncryptionKey() {
    return encryptionKey;
  }

  public String getEncryptionKeyBase64() {
    return Base64.getEncoder().encodeToString(encryptionKey.getEncoded());
  }
}
