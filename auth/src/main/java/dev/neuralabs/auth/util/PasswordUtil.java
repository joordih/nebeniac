package dev.neuralabs.auth.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordUtil {

  private static final String ALGORITHM = "SHA-256";
  private static final int SALT_LENGTH = 32;


  public static String hashPassword(String password) {
    try {

      SecureRandom random = new SecureRandom();
      byte[] salt = new byte[SALT_LENGTH];
      random.nextBytes(salt);


      MessageDigest md = MessageDigest.getInstance(ALGORITHM);
      md.update(salt);
      byte[] hashedPassword = md.digest(password.getBytes());


      byte[] combined = new byte[salt.length + hashedPassword.length];
      System.arraycopy(salt, 0, combined, 0, salt.length);
      System.arraycopy(hashedPassword, 0, combined, salt.length, hashedPassword.length);

      return Base64.getEncoder().encodeToString(combined);

    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("Error generating password hash", e);
    }
  }


  public static boolean verifyPassword(String password, String storedHash) {
    try {

      byte[] combined = Base64.getDecoder().decode(storedHash);


      byte[] salt = new byte[SALT_LENGTH];
      byte[] storedPasswordHash = new byte[combined.length - SALT_LENGTH];
      System.arraycopy(combined, 0, salt, 0, SALT_LENGTH);
      System.arraycopy(combined, SALT_LENGTH, storedPasswordHash, 0, storedPasswordHash.length);


      MessageDigest md = MessageDigest.getInstance(ALGORITHM);
      md.update(salt);
      byte[] testHash = md.digest(password.getBytes());


      return MessageDigest.isEqual(storedPasswordHash, testHash);

    } catch (Exception e) {
      return false;
    }
  }


  public static String generateTemporaryPassword(int length) {
    String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    SecureRandom random = new SecureRandom();
    StringBuilder password = new StringBuilder();

    for (int i = 0; i < length; i++) {
      password.append(chars.charAt(random.nextInt(chars.length())));
    }

    return password.toString();
  }


  public static String generateToken() {
    SecureRandom random = new SecureRandom();
    byte[] token = new byte[32];
    random.nextBytes(token);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
  }
}
