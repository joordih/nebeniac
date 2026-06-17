package dev.neuralabs.protector.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;


public class KeyDerivation {

  private static final Logger logger = LoggerFactory.getLogger(KeyDerivation.class);
  private static final String ALGORITHM = "AES";
  private static final String HMAC_ALG = "HmacSHA256";
  private static final int KEY_LEN = 32;

  // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
  private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
    Mac mac = Mac.getInstance(HMAC_ALG);
    mac.init(new SecretKeySpec(salt, HMAC_ALG));
    return mac.doFinal(ikm);
  }

  // HKDF-Expand: OKM = HKDF-Expand(PRK, info, L)
  private static byte[] hkdfExpand(byte[] prk, byte[] info, int len) throws Exception {
    Mac mac = Mac.getInstance(HMAC_ALG);
    mac.init(new SecretKeySpec(prk, HMAC_ALG));
    byte[] t = new byte[0];
    byte[] okm = new byte[len];
    int pos = 0;
    byte counter = 1;
    while (pos < len) {
      mac.reset();
      mac.update(t);
      mac.update(info);
      mac.update(counter);
      t = mac.doFinal();
      int copyLen = Math.min(t.length, len - pos);
      System.arraycopy(t, 0, okm, pos, copyLen);
      pos += copyLen;
      counter++;
    }
    Arrays.fill(t, (byte) 0);
    return okm;
  }

  /**
   * Derives an AES key using HKDF with per-license salt and optional server pepper.
   * This replaces the weak SHA-256 KDF with a cryptographically secure HKDF.
   * 
   * @param licenseKey The license key
   * @param pluginId The plugin identifier
   * @param perLicenseSalt Unique random salt per license (should be stored with license)
   * @param serverPepper Optional server-side secret (can be null for backward compatibility)
   * @return Derived AES SecretKey
   */
  public static SecretKey deriveKeyFromLicense(String licenseKey, String pluginId, byte[] perLicenseSalt, byte[] serverPepper) {
    try {
      byte[] ikm = (licenseKey + ":" + pluginId).getBytes(StandardCharsets.UTF_8);
      byte[] info = "Nebeniac-AES-256-GCM".getBytes(StandardCharsets.UTF_8);

      // Combine per-license salt with server pepper if provided
      byte[] combinedSalt;
      if (serverPepper != null && serverPepper.length > 0) {
        combinedSalt = new byte[perLicenseSalt.length + serverPepper.length];
        System.arraycopy(perLicenseSalt, 0, combinedSalt, 0, perLicenseSalt.length);
        System.arraycopy(serverPepper, 0, combinedSalt, perLicenseSalt.length, serverPepper.length);
      } else {
        combinedSalt = perLicenseSalt;
      }

      byte[] prk = hkdfExtract(combinedSalt, ikm);
      byte[] keyBytes = hkdfExpand(prk, info, KEY_LEN);

      SecretKey secretKey = new SecretKeySpec(keyBytes, ALGORITHM);

      // Clear sensitive data
      Arrays.fill(ikm, (byte) 0);
      Arrays.fill(prk, (byte) 0);
      Arrays.fill(keyBytes, (byte) 0);
      Arrays.fill(combinedSalt, (byte) 0);

      logger.info("Key derived successfully using HKDF for plugin: {}", pluginId);

      return secretKey;

    } catch (Exception e) {
      logger.error("Error derivando clave de cifrado con HKDF", e);
      throw new RuntimeException("Error derivando clave de cifrado", e);
    }
  }

  /**
   * Legacy method for backward compatibility - generates a random salt if none provided.
   * WARNING: This should only be used during migration. New code should use the method with explicit salt.
   */
  @Deprecated
  public static SecretKey deriveKeyFromLicense(String licenseKey, String pluginId) {
    logger.warn("Using deprecated KDF method without explicit salt - generating random salt");
    byte[] randomSalt = new byte[32];
    try {
      SecureRandom.getInstanceStrong().nextBytes(randomSalt);
    } catch (Exception e) {
      new SecureRandom().nextBytes(randomSalt);
    }
    return deriveKeyFromLicense(licenseKey, pluginId, randomSalt, null);
  }


  public static String deriveKeyFromLicenseAsBase64(String licenseKey, String pluginId) {
    SecretKey key = deriveKeyFromLicense(licenseKey, pluginId);
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }


  public static boolean verifyDerivedKey(String licenseKey, String pluginId, String expectedKeyBase64) {
    try {
      String derivedKey = deriveKeyFromLicenseAsBase64(licenseKey, pluginId);
      return derivedKey.equals(expectedKeyBase64);
    } catch (Exception e) {
      logger.error("Error verifying derived key", e);
      return false;
    }
  }


  private static String maskLicenseKey(String licenseKey) {
    if (licenseKey == null || licenseKey.length() < 8) {
      return "***";
    }
    return licenseKey.substring(0, 4) + "***" + licenseKey.substring(licenseKey.length() - 4);
  }


  public static boolean testKeyDerivation() {
    try {
      String testLicense = "TEST-1234-5678-9012";
      String testPlugin = "test-plugin-v1.0";
      byte[] testSalt = new byte[32];
      SecureRandom.getInstanceStrong().nextBytes(testSalt);

      SecretKey key1 = deriveKeyFromLicense(testLicense, testPlugin, testSalt, null);
      SecretKey key2 = deriveKeyFromLicense(testLicense, testPlugin, testSalt, null);

      boolean identical = Arrays.equals(key1.getEncoded(), key2.getEncoded());

      String differentLicense = "TEST-9876-5432-1098";
      SecretKey key3 = deriveKeyFromLicense(differentLicense, testPlugin, testSalt, null);
      boolean different = !Arrays.equals(key1.getEncoded(), key3.getEncoded());

      boolean success = identical && different;

      if (success) {
        logger.info("HKDF key derivation test passed");
      } else {
        logger.error("HKDF key derivation test failed");
      }

      return success;

    } catch (Exception e) {
      logger.error("HKDF key derivation test failed with exception", e);
      return false;
    }
  }
}
