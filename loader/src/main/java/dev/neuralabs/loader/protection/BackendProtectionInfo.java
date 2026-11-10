package dev.neuralabs.loader.protection;

import dev.neuralabs.loader.service.BackendService;
import lombok.Getter;

import java.util.Base64;
import java.util.List;
import java.util.logging.Logger;

@Getter
public class BackendProtectionInfo {
  private final Logger logger;
  private final BackendService backendService;
  private final String licenseKey;
  private final String hardwareFingerprint;
  private String sessionToken;

  private BackendService.PluginMetadata pluginMetadata;
  private boolean loaded = false;

  public BackendProtectionInfo(Logger logger, BackendService backendService, String licenseKey,
      String hardwareFingerprint, String sessionToken) {
    this.logger = logger;
    this.backendService = backendService;
    this.licenseKey = licenseKey;
    this.hardwareFingerprint = hardwareFingerprint;
    this.sessionToken = sessionToken;
  }

  public boolean loadProtectionInfo() {
    if (loaded && pluginMetadata != null) {
      return true;
    }

    try {
      logger.info("Verifying license with backend...");
      BackendService.LicenseVerificationResult verificationResult = backendService.verifyLicense(
          licenseKey,
          hardwareFingerprint,
          new BackendService.ServerInfo("unknown", 25565, "unknown", "unknown"));

      if (verificationResult == null || !verificationResult.isSuccess()
          || verificationResult.getSessionToken() == null
          || verificationResult.getSessionToken().isBlank()) {
        throw new IllegalStateException("License verification failed or session token not provided");
      }

      String issuedSessionToken = verificationResult.getSessionToken();
      this.sessionToken = issuedSessionToken;

      logger.info("Requesting plugin metadata from backend with session token...");

      pluginMetadata = backendService.getPluginMetadata(licenseKey, hardwareFingerprint, issuedSessionToken);

      loaded = true;

      logger.info("Plugin metadata loaded successfully:");
      logger.info("  - Plugin ID: " + pluginMetadata.getPluginId());
      logger.info("  - Plugin Name: " + pluginMetadata.getPluginName());
      logger.info("  - Plugin Version: " + pluginMetadata.getPluginVersion());
      logger.info("  - Original Main Class: " + pluginMetadata.getOriginalMainClass());
      logger.info("  - Encryption Key: [REDACTED]");
      logger.info("  - Target Packages: "
          + (pluginMetadata.getTargetPackages() != null
              ? String.join(", ", pluginMetadata.getTargetPackages())
              : "null"));

      return true;
    } catch (Exception e) {
      logger.severe("Failed to load plugin metadata from backend: " + e.getMessage());
      loaded = false;
      pluginMetadata = null;
      return false;
    }
  }

  public boolean isAvailable() {
    return loadProtectionInfo() && pluginMetadata != null;
  }

  public String getEncryptionKey() {
    if (!isAvailable()) {
      return null;
    }
    return pluginMetadata.getEncryptionKey();
  }

  public String getOriginalMainClass() {
    if (!isAvailable()) {
      return null;
    }
    return pluginMetadata.getOriginalMainClass();
  }

  public byte[] getEncryptionKeyBytes() {
    String key = getEncryptionKey();
    if (key != null) {
      try {
        return Base64.getDecoder().decode(key);
      } catch (Exception e) {
        logger.warning("Error decoding encryption key: " + e.getMessage());
      }
    }
    return null;
  }

  public BackendService.PluginMetadata getPluginMetadata() {
    if (!isAvailable()) {
      return null;
    }
    return pluginMetadata;
  }

  public boolean reload() {
    loaded = false;
    pluginMetadata = null;
    return loadProtectionInfo();
  }

  public List<String> getTargetPackages() {
    if (!isAvailable() || pluginMetadata == null) {
      return null;
    }
    return pluginMetadata.getTargetPackages();
  }
}
