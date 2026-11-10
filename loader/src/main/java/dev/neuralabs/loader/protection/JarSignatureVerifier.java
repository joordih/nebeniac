package dev.neuralabs.loader.protection;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.Signature;
import java.security.PublicKey;
import java.util.Base64;
import java.util.logging.Logger;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public final class JarSignatureVerifier {
  private static final String SIGNATURE_ALGORITHM = "Ed25519";

  private JarSignatureVerifier() {
  }

  public static boolean verify(File jarFile, String signatureBase64, PublicKey publicKey, Logger logger)
      throws Exception {
    if (logger != null) {
      logger.info("Starting JAR signature verification for: " + jarFile.getName());
    }

    byte[] jarHash = calculateJarHash(jarFile);

    if (logger != null) {
      logger.fine("JAR hash calculated (SHA-256 length): " + jarHash.length + " bytes");

      StringBuilder hashPreview = new StringBuilder();
      for (int i = 0; i < Math.min(16, jarHash.length); i++) {
        hashPreview.append(String.format("%02x", jarHash[i]));
      }
      logger.fine("JAR hash preview (first 16 bytes): " + hashPreview.toString() + "...");
    }

    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    Signature signature;
    try {
      signature = Signature.getInstance(SIGNATURE_ALGORITHM, "BC");
      if (logger != null) {
        logger.fine("Using Ed25519 signature algorithm");
      }
    } catch (NoSuchAlgorithmException e) {
      signature = Signature.getInstance("EdDSA", "BC");
      if (logger != null) {
        logger.info("Using EdDSA instead of Ed25519 for signature verification");
      }
    }

    signature.initVerify(publicKey);
    signature.update(jarHash);

    byte[] signatureBytes = decodeBase64Flexible(signatureBase64);

    if (logger != null) {
      logger.fine("Signature bytes decoded (length): " + signatureBytes.length + " bytes");
    }

    boolean valid = signature.verify(signatureBytes);

    if (!valid && logger != null) {
      logger.severe("Signature verification FAILED for JAR: " + jarFile.getName());
      logger.severe("JAR hash length: " + jarHash.length + " bytes");
      logger.severe("Signature length: " + signatureBytes.length + " bytes");
      logger.severe("Public key algorithm: " + publicKey.getAlgorithm());
      logger.severe("Public key format: " + publicKey.getFormat());
    } else if (valid && logger != null) {
      logger.info("Signature verification PASSED for JAR: " + jarFile.getName());
    }

    return valid;
  }

  private static byte[] decodeBase64Flexible(String base64String) {
    try {
      return Base64.getUrlDecoder().decode(addBase64Padding(base64String));
    } catch (IllegalArgumentException e) {
      return Base64.getDecoder().decode(base64String);
    }
  }

  private static String addBase64Padding(String base64) {
    int mod = base64.length() % 4;
    if (mod == 0) {
      return base64;
    }
    return base64 + "=".repeat(4 - mod);
  }

  private static byte[] calculateJarHash(File jarFile) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");

    try (JarFile jar = new JarFile(jarFile)) {
      jar.stream()
          .filter(entry -> !entry.isDirectory())
          .filter(JarSignatureVerifier::isProtectedEntry)
          .sorted((e1, e2) -> e1.getName().compareTo(e2.getName()))
          .forEach(entry -> updateDigest(jar, entry, digest));
    }

    return digest.digest();
  }

  private static boolean isProtectedEntry(JarEntry entry) {
    String name = entry.getName();
    return name.endsWith(".encrypted") ||
        name.endsWith(".iv") ||
        name.equals("plugin.yml");
  }

  private static void updateDigest(JarFile jar, JarEntry entry, MessageDigest digest) {
    try {
      digest.update(entry.getName().getBytes(StandardCharsets.UTF_8));
      try (InputStream is = jar.getInputStream(entry)) {
        byte[] buffer = new byte[8192];
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
          digest.update(buffer, 0, bytesRead);
        }
      }
    } catch (Exception e) {
      throw new RuntimeException("Error hashing JAR entry: " + entry.getName(), e);
    }
  }
}
