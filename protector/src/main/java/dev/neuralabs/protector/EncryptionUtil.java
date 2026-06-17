package dev.neuralabs.protector;

import dev.neuralabs.protector.util.AESUtil;
import dev.neuralabs.protector.util.AESUtil.EncryptedData;
import dev.neuralabs.protector.util.KeyDerivation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class EncryptionUtil {
  private static final Logger logger = LoggerFactory.getLogger(EncryptionUtil.class);

  private final SecretKey encryptionKey;
  private final byte[] perLicenseSalt;
  private final byte[] serverPepper;
  private String licenseKey;
  private String pluginId;

  public EncryptionUtil() throws NoSuchAlgorithmException {
    this.encryptionKey = AESUtil.generateKey();
    this.perLicenseSalt = null;
    this.serverPepper = null;
    logger.warn("Using legacy random AES key - per-license salt not provided.");
  }

  public EncryptionUtil(String licenseKey, String pluginId) {

    this.licenseKey = licenseKey;
    this.pluginId = pluginId;

    byte[] salt = null;
    byte[] pepper = null;
    try {
      String saltB64 = System.getenv("NEBENIAC_LICENSE_SALT");
      String pepperB64 = System.getenv("NEBENIAC_SERVER_PEPPER");
      if (saltB64 != null && !saltB64.isBlank()) {
        salt = Base64.getDecoder().decode(saltB64);
      }
      if (pepperB64 != null && !pepperB64.isBlank()) {
        pepper = Base64.getDecoder().decode(pepperB64);
      }
    } catch (Exception e) {
      logger.warn("Failed to read salt/pepper from environment: {}", e.getMessage());
    }

    if (salt != null) {
      this.perLicenseSalt = salt;
      this.serverPepper = pepper;
      this.encryptionKey = KeyDerivation.deriveKeyFromLicense(licenseKey, pluginId, this.perLicenseSalt,
          this.serverPepper);
      logger.info("Clave de cifrado derivada usando HKDF para plugin: {}", pluginId);
    } else {
      this.perLicenseSalt = null;
      this.serverPepper = pepper;
      this.encryptionKey = KeyDerivation.deriveKeyFromLicense(licenseKey, pluginId);
      logger.warn("Per-license salt not provided in env for plugin {}, using legacy derivation", pluginId);
    }
  }

  public EncryptionUtil(String licenseKey, String pluginId, String perLicenseSaltBase64, byte[] serverPepper) {
    this.licenseKey = licenseKey;
    this.pluginId = pluginId;
    this.serverPepper = serverPepper != null ? serverPepper.clone() : null;
    if (perLicenseSaltBase64 != null && !perLicenseSaltBase64.isBlank()) {
      this.perLicenseSalt = decodeSalt(perLicenseSaltBase64);
      this.encryptionKey = KeyDerivation.deriveKeyFromLicense(licenseKey, pluginId, this.perLicenseSalt,
          this.serverPepper);
      logger.info("Clave de cifrado derivada usando HKDF para plugin: {}", pluginId);
    } else {
      this.perLicenseSalt = null;
      logger.warn("Per-license salt not provided for plugin {}, falling back to legacy derivation", pluginId);
      this.encryptionKey = KeyDerivation.deriveKeyFromLicense(licenseKey, pluginId);
    }
  }

  public EncryptedData encryptClass(byte[] classBytes) throws Exception {
    return AESUtil.encrypt(classBytes, encryptionKey);
  }

  public SecretKey getEncryptionKey() {
    return encryptionKey;
  }

  private byte[] decodeSalt(String perLicenseSaltBase64) {
    try {
      return Base64.getDecoder().decode(perLicenseSaltBase64.replace(" ", ""));
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid per-license salt format", e);
    }
  }

  public String getEncryptionKeyBase64() {
    return Base64.getEncoder().encodeToString(encryptionKey.getEncoded());
  }

  public String getLicenseKey() {
    return licenseKey;
  }

  public String getPluginId() {
    return pluginId;
  }
}
