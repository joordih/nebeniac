package dev.neuralabs.auth.util;

import dev.neuralabs.auth.config.AuthConfig;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import org.mindrot.jbcrypt.BCrypt;

public final class PasswordUtil {
  private static final int BCRYPT_COST = 12;
  private static final int BCRYPT_MAX_BYTES = 72;
  private static final String BCRYPT_PREFIX = "$2a$" + BCRYPT_COST + "$";
  private static final int LEGACY_SALT_LENGTH = 32;
  private static final SecureRandom RANDOM = new SecureRandom();

  private PasswordUtil() {}

  public static String hashPassword(String password) {
    return BCrypt.hashpw(password, BCrypt.gensalt(BCRYPT_COST, RANDOM));
  }

  public static boolean verifyPassword(String password, String storedHash) {
    if (password == null || storedHash == null) {
      return false;
    }
    try {
      return storedHash.startsWith("$2")
          ? BCrypt.checkpw(password, storedHash)
          : verifyLegacySha256(password, storedHash);
    } catch (RuntimeException e) {
      return false;
    }
  }

  public static boolean needsRehash(String storedHash) {
    return storedHash == null || !storedHash.startsWith(BCRYPT_PREFIX);
  }

  public static String validatePassword(String password, AuthConfig config) {
    if (password == null || password.length() < config.getPasswordMinLength()) {
      return "Password must be at least " + config.getPasswordMinLength() + " characters";
    }

    if (password.getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_BYTES) {
      return "Password must be at most " + BCRYPT_MAX_BYTES + " bytes";
    }

    if (config.isPasswordRequireUppercase() && !password.matches(".*[A-Z].*")) {
      return "Password must contain at least one uppercase letter";
    }

    if (config.isPasswordRequireLowercase() && !password.matches(".*[a-z].*")) {
      return "Password must contain at least one lowercase letter";
    }

    if (config.isPasswordRequireNumbers() && !password.matches(".*\\d.*")) {
      return "Password must contain at least one number";
    }

    if (config.isPasswordRequireSpecialChars() && !password.matches(".*[^A-Za-z0-9].*")) {
      return "Password must contain at least one special character";
    }

    return null;
  }

  public static String generateToken() {
    byte[] token = new byte[32];
    RANDOM.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }

  private static boolean verifyLegacySha256(String password, String storedHash) {
    byte[] combined = Base64.getDecoder().decode(storedHash);
    if (combined.length <= LEGACY_SALT_LENGTH) {
      return false;
    }
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(combined, 0, LEGACY_SALT_LENGTH);
      byte[] testHash = md.digest(password.getBytes());
      byte[] storedPasswordHash = new byte[combined.length - LEGACY_SALT_LENGTH];
      System.arraycopy(combined, LEGACY_SALT_LENGTH, storedPasswordHash, 0, storedPasswordHash.length);
      return MessageDigest.isEqual(storedPasswordHash, testHash);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
