package dev.neuralabs.loader.service;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.neuralabs.loader.crypto.e2ee.E2EEResponseDecryptor;
import dev.neuralabs.loader.crypto.e2ee.TinkE2EEClient;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.List;
import java.util.logging.Logger;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Value;

public class BackendService {

  private final String serverUrl;
  private final HttpClient httpClient;
  private final Gson gson;
  private final Logger logger;
  private final TinkE2EEClient e2eeClient;
  private final E2EEResponseDecryptor responseDecryptor;
  private final boolean e2eeEnabled;
  private final boolean requireE2EE;

  public BackendService(String serverUrl, Logger logger) {
    this(serverUrl, logger, true); // SECURITY: E2EE required by default
  }

  public BackendService(String serverUrl, Logger logger, boolean requireE2EE) {
    this.serverUrl = serverUrl.endsWith("/")
        ? serverUrl.substring(0, serverUrl.length() - 1)
        : serverUrl;
    this.logger = logger;
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();
    this.gson = new GsonBuilder()
        .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        .create();
    this.requireE2EE = requireE2EE;

    TinkE2EEClient tempE2EE = null;
    boolean tempEnabled = false;
    try {
      tempE2EE = new TinkE2EEClient(logger);
      if (tempE2EE.isInitialized()) {
        tempEnabled = true;
        logger.info(
            "E2EE encryption enabled for backend communication");
      } else {
        logger.warning("E2EE client initialized but not ready");
      }
    } catch (Exception e) {
      logger.warning(
          "Failed to initialize E2EE client: " + e.getMessage());
    }

    // SECURITY FIX: Enforce E2EE requirement - do not fall back to plaintext
    if (this.requireE2EE && !tempEnabled) {
      throw new IllegalStateException(
          "E2EE is required but not available. Cannot proceed with plaintext communication for security reasons.");
    }

    this.e2eeClient = tempE2EE;
    this.e2eeEnabled = tempEnabled;

    E2EEResponseDecryptor tempDecryptor = null;
    if (tempEnabled) {
      try {
        tempDecryptor = new E2EEResponseDecryptor(logger);
        logger.info("E2EE response decryption enabled");
      } catch (Exception e) {
        logger.warning(
            "Failed to initialize response decryptor: " + e.getMessage());
        if (requireE2EE) {
          throw new IllegalStateException(
              "E2EE response decryptor is required but failed to initialize");
        }
      }
    }
    this.responseDecryptor = tempDecryptor;
  }

  public PluginMetadata getPluginMetadata(
      String licenseKey,
      String hardwareFingerprint,
      String sessionToken) throws IOException {
    try {
      MetadataRequest request = new MetadataRequest();
      request.setLicenseKey(licenseKey);
      request.setHardwareFingerprint(hardwareFingerprint);
      request.setSessionToken(sessionToken);

      String requestBody = gson.toJson(request);

      if (e2eeEnabled && e2eeClient != null) {
        try {
          requestBody = e2eeClient.encryptPayload(requestBody);
          logger.info("Encrypted metadata request with E2EE");
        } catch (GeneralSecurityException e) {
          if (this.requireE2EE) {
            throw new IllegalStateException("E2EE is required but request encryption failed: " + e.getMessage(), e);
          } else {
            logger.warning("Failed to encrypt request, proceeding without E2EE: " + e.getMessage());
          }
        }
      }

      HttpRequest httpRequest = HttpRequest.newBuilder()
          .uri(URI.create(serverUrl + "/api/v1/plugins/metadata"))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .timeout(Duration.ofSeconds(30))
          .build();

      HttpResponse<String> response = httpClient.send(
          httpRequest,
          HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 200) {

        String responseBody = decryptResponseIfNeeded(

            response.body(),

            sessionToken);

        MetadataResponse metadataResponse = gson.fromJson(
            responseBody,
            MetadataResponse.class);
        if (metadataResponse.isSuccess()) {
          logger.info(
              "Plugin metadata retrieved successfully for plugin: " +
                  metadataResponse.getPluginId());
          return new PluginMetadata(
              metadataResponse.getPluginId(),
              metadataResponse.getEncryptionKey(),
              metadataResponse.getOriginalMainClass(),
              metadataResponse.getPluginName(),
              metadataResponse.getPluginVersion(),
              metadataResponse.getTargetPackages());
        } else {
          throw new IOException(
              "Backend error: " + metadataResponse.getError());
        }
      } else {
        logger.warning(
            "Failed to get plugin metadata. Status: " +
                response.statusCode() +
                ", Body: " +
                response.body());
        throw new IOException(
            "Failed to get plugin metadata: HTTP " +
                response.statusCode());
      }

    } catch (InterruptedException e) {

      Thread.currentThread().interrupt();

      throw new IOException("Request interrupted", e);

    } finally {

      if (sessionToken != null) {
        clearSessionKey(sessionToken);
      }
    }
  }

  public LicenseVerificationResult verifyLicense(
      String licenseKey,
      String hardwareFingerprint,
      ServerInfo serverInfo) throws IOException {
    try {
      VerifyRequest request = new VerifyRequest();
      request.setLicenseKey(licenseKey);
      request.setHardwareFingerprint(hardwareFingerprint);
      request.setServerInfo(serverInfo);
      request.setPluginVersion("1.0.0");
      request.setClientTimestamp(System.currentTimeMillis());

      String requestBody = gson.toJson(request);

      if (e2eeEnabled && e2eeClient != null) {
        try {
          requestBody = e2eeClient.encryptPayload(requestBody);
          logger.info(
              "Encrypted license verification request with E2EE");
        } catch (GeneralSecurityException e) {
          if (this.requireE2EE) {
            throw new IllegalStateException("E2EE is required but request encryption failed: " + e.getMessage(), e);
          } else {
            logger.warning("Failed to encrypt request, proceeding without E2EE: " + e.getMessage());
          }
        }
      }

      HttpRequest httpRequest = HttpRequest.newBuilder()
          .uri(URI.create(serverUrl + "/api/v1/verify"))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .timeout(Duration.ofSeconds(30))
          .build();

      HttpResponse<String> response = httpClient.send(
          httpRequest,
          HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 200) {

        String responseBody = decryptResponseIfNeeded(
            response.body(),
            null);

        VerifyResponse verifyResponse = gson.fromJson(
            responseBody,
            VerifyResponse.class);
        if (verifyResponse.isSuccess()) {
          logger.info("License verified successfully");
          return new LicenseVerificationResult(
              true,
              verifyResponse.getSessionToken(),
              verifyResponse.getExpiresIn(),
              verifyResponse.getFeatures(),
              verifyResponse.getLicenseType(),
              null);
        } else {
          return new LicenseVerificationResult(
              false,
              null,
              0,
              null,
              null,
              verifyResponse.getError());
        }
      } else {
        logger.warning(
            "License verification failed. Status: " +
                response.statusCode());
        return new LicenseVerificationResult(
            false,
            null,
            0,
            null,
            null,
            "HTTP " + response.statusCode());
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Request interrupted", e);
    }
  }

  private String decryptResponseIfNeeded(
      String responseBody,
      String sessionToken) {
    if (responseDecryptor == null || !responseDecryptor.isInitialized()) {
      return responseBody;
    }

    if (!responseDecryptor.isEncryptedResponse(responseBody)) {

      if (sessionToken == null || sessionToken.isEmpty()) {

        logger.fine("Received plaintext response from backend; proceeding without decryption (no session token)");
        return responseBody;
      }
      throw new IllegalStateException("Expected encrypted response from backend but received plaintext");

    }

    try {
      String decrypted = responseDecryptor.decryptResponse(
          responseBody,
          sessionToken);
      logger.fine("Successfully decrypted server response");
      return decrypted;
    } catch (E2EEResponseDecryptor.DecryptionException e) {
      throw new IllegalStateException("Failed to decrypt E2EE response", e);
    }
  }

  public void clearSessionKey(String sessionToken) {
    if (responseDecryptor != null) {
      responseDecryptor.clearSessionKey(sessionToken);
    }
  }

  public boolean isE2EEEnabled() {
    return e2eeEnabled;
  }

  @Value
  public static class PluginMetadata {

    String pluginId;
    String encryptionKey;
    String originalMainClass;
    String pluginName;
    String pluginVersion;
    List<String> targetPackages;
  }

  @Data
  @AllArgsConstructor
  public static class LicenseVerificationResult {

    private final boolean success;
    private final String sessionToken;
    private final int expiresIn;
    private final List<String> features;
    private final String licenseType;
    private final String error;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class ServerInfo {

    private String serverName;
    private int serverPort;
    private String minecraftVersion;
    private String serverSoftware;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  private static class MetadataRequest {

    private String licenseKey;
    private String hardwareFingerprint;
    private String sessionToken;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  private static class MetadataResponse {

    private boolean success;
    private String pluginId;
    private String encryptionKey;
    private String originalMainClass;
    private String pluginName;
    private String pluginVersion;
    private List<String> targetPackages;
    private String error;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  private static class VerifyRequest {

    private String licenseKey;
    private String hardwareFingerprint;
    private ServerInfo serverInfo;
    private String pluginVersion;
    private long clientTimestamp;
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  private static class VerifyResponse {

    private boolean success;
    private String sessionToken;
    private int expiresIn;
    private List<String> features;
    private String licenseType;
    private String error;
  }
}
