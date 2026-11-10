package dev.neuralabs.loader.service;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.neuralabs.loader.crypto.e2ee.E2EEResponseDecryptor;
import dev.neuralabs.loader.crypto.e2ee.TinkE2EEClient;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
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

  public BackendService(String serverUrl, Logger logger) {
    String normalized = serverUrl.endsWith("/")
        ? serverUrl.substring(0, serverUrl.length() - 1)
        : serverUrl;
    requireSecureTransport(normalized);
    this.serverUrl = normalized;
    this.logger = logger;
    this.httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();
    this.gson = new GsonBuilder()
        .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        .create();

    this.e2eeClient = new TinkE2EEClient(logger);
    if (!e2eeClient.isInitialized()) {
      throw new IllegalStateException("E2EE client could not be initialized; refusing to contact the backend");
    }
    logger.info("E2EE encryption enabled for backend communication");
  }

  public PluginMetadata getPluginMetadata(
      String licenseKey,
      String hardwareFingerprint,
      String sessionToken) throws IOException {
    MetadataRequest request = new MetadataRequest(licenseKey, hardwareFingerprint, sessionToken);
    MetadataResponse metadataResponse = postEncrypted("/api/v1/plugins/metadata", request, MetadataResponse.class);

    if (metadataResponse == null || !metadataResponse.isSuccess()) {
      throw new IOException("Backend error: " + (metadataResponse != null ? metadataResponse.getError() : "empty response"));
    }

    logger.info("Plugin metadata retrieved successfully for plugin: " + metadataResponse.getPluginId());
    return new PluginMetadata(
        metadataResponse.getPluginId(),
        metadataResponse.getEncryptionKey(),
        metadataResponse.getOriginalMainClass(),
        metadataResponse.getPluginName(),
        metadataResponse.getPluginVersion(),
        metadataResponse.getTargetPackages());
  }

  public LicenseVerificationResult verifyLicense(
      String licenseKey,
      String hardwareFingerprint,
      ServerInfo serverInfo) throws IOException {
    VerifyRequest request = new VerifyRequest(
        licenseKey, hardwareFingerprint, serverInfo, "1.0.0", System.currentTimeMillis());

    VerifyResponse verifyResponse;
    try {
      verifyResponse = postEncrypted("/api/v1/verify", request, VerifyResponse.class);
    } catch (BackendHttpException e) {
      logger.warning("License verification failed. Status: " + e.getStatusCode());
      return new LicenseVerificationResult(false, null, 0, null, null, "HTTP " + e.getStatusCode());
    }

    if (verifyResponse == null || !verifyResponse.isSuccess()) {
      return new LicenseVerificationResult(false, null, 0, null, null,
          verifyResponse != null ? verifyResponse.getError() : "empty response");
    }

    logger.info("License verified successfully");
    return new LicenseVerificationResult(
        true,
        verifyResponse.getSessionToken(),
        verifyResponse.getExpiresIn(),
        verifyResponse.getFeatures(),
        verifyResponse.getLicenseType(),
        null);
  }

  private <T> T postEncrypted(String path, Object payload, Class<T> responseType) throws IOException {
    TinkE2EEClient.EncryptedRequest encrypted;
    try {
      encrypted = e2eeClient.encryptPayload(gson.toJson(payload));
    } catch (GeneralSecurityException e) {
      throw new IOException("Request encryption failed", e);
    }

    try {
      HttpRequest httpRequest = HttpRequest.newBuilder()
          .uri(URI.create(serverUrl + path))
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(encrypted.getBody()))
          .timeout(Duration.ofSeconds(30))
          .build();

      HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() != 200) {
        throw new BackendHttpException(response.statusCode());
      }

      String plaintext = E2EEResponseDecryptor.decrypt(response.body(), encrypted);
      return gson.fromJson(plaintext, responseType);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Request interrupted", e);
    } catch (E2EEResponseDecryptor.DecryptionException e) {
      throw new IOException("Rejected backend response: " + e.getMessage(), e);
    } finally {
      encrypted.destroy();
    }
  }

  private static void requireSecureTransport(String serverUrl) {
    URI uri = URI.create(serverUrl);
    String scheme = uri.getScheme();
    if ("https".equalsIgnoreCase(scheme)) {
      return;
    }
    if ("http".equalsIgnoreCase(scheme) && isLoopback(uri.getHost())) {
      return;
    }
    throw new IllegalStateException("Backend server-url must use https:// (plain http is only allowed for localhost)");
  }

  private static boolean isLoopback(String host) {
    if (host == null) {
      return false;
    }
    try {
      return InetAddress.getByName(host).isLoopbackAddress();
    } catch (UnknownHostException e) {
      return false;
    }
  }

  public static final class BackendHttpException extends IOException {
    private final int statusCode;

    BackendHttpException(int statusCode) {
      super("Backend returned HTTP " + statusCode);
      this.statusCode = statusCode;
    }

    public int getStatusCode() {
      return statusCode;
    }
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
