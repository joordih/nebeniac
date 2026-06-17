package dev.neuralabs.loader.license;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.logging.Logger;

public class LicenseManager {

  private final Logger logger;
  private final String serverUrl;

  public LicenseManager(Logger logger) {
    this.logger = logger;
    this.serverUrl = "http://localhost:8080";
  }

  public boolean verifyLicense(String licenseKey) {
    try {
      logger.info("Verifying license: " + licenseKey.substring(0, Math.min(8, licenseKey.length())) + "...");

      URL url = URI.create(serverUrl + "/api/v1/verify").toURL();
      HttpURLConnection connection = (HttpURLConnection) url.openConnection();

      connection.setRequestMethod("POST");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setRequestProperty("User-Agent", "SecurePluginLoader/1.0");
      connection.setDoOutput(true);
      connection.setConnectTimeout(10000);
      connection.setReadTimeout(15000);

      String jsonRequest = createVerificationRequest(licenseKey);

      try (OutputStream os = connection.getOutputStream()) {
        byte[] input = jsonRequest.getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
      }

      int responseCode = connection.getResponseCode();

      if (responseCode == 200) {
        try (BufferedReader br = new BufferedReader(
            new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))) {
          StringBuilder response = new StringBuilder();
          String responseLine;
          while ((responseLine = br.readLine()) != null) {
            response.append(responseLine.trim());
          }

          boolean isValid = response.toString().contains("\"success\":true");
          if (isValid) {
            logger.info("License verified successfully");
          } else {
            logger.warning("License is invalid or expired");
          }
          return isValid;
        }
      } else {
        logger.warning("HTTP error verifying license: " + responseCode);
        return false;
      }

    } catch (Exception e) {
      logger.warning("Error verifying license: " + e.getMessage());
      return false;
    }
  }

  private String createVerificationRequest(String licenseKey) {
    String json = "{" +
        "\"licenseKey\":\"" + licenseKey + "\"," +
        "\"hardwareFingerprint\":\"" + generateHardwareFingerprint() + "\"," +
        "\"serverInfo\":{" +
        "\"serverName\":\"Minecraft Server\"," +
        "\"serverPort\":25565," +
        "\"minecraftVersion\":\"1.8\"," +
        "\"serverSoftware\":\"Spigot\"" +
        "}," +
        "\"pluginVersion\":\"1.0.0\"," +
        "\"clientTimestamp\":" + System.currentTimeMillis() +
        "}";
    return json;
  }

  private String generateHardwareFingerprint() {
    try {
      String osName = System.getProperty("os.name", "unknown");
      String osVersion = System.getProperty("os.version", "unknown");
      String osArch = System.getProperty("os.arch", "unknown");
      String userName = System.getProperty("user.name", "unknown");
      String javaVersion = System.getProperty("java.version", "unknown");

      String combined = osName + "|" + osVersion + "|" + osArch + "|" +
          userName + "|" + javaVersion;

      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hash = md.digest(combined.getBytes(StandardCharsets.UTF_8));

      StringBuilder hexString = new StringBuilder();
      for (byte b : hash) {
        String hex = Integer.toHexString(0xff & b);
        if (hex.length() == 1) {
          hexString.append('0');
        }
        hexString.append(hex);
      }

      return hexString.toString();

    } catch (Exception e) {
      return "fallback-" + System.currentTimeMillis();
    }
  }
}
