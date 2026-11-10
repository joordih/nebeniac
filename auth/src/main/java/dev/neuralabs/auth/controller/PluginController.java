package dev.neuralabs.auth.controller;

import static dev.neuralabs.auth.controller.ControllerSupport.bearerClaims;
import static dev.neuralabs.auth.controller.ControllerSupport.error;
import static dev.neuralabs.auth.controller.ControllerSupport.isEncryptedPayload;
import static dev.neuralabs.auth.controller.ControllerSupport.maskLicenseKey;

import com.google.gson.Gson;
import dev.neuralabs.auth.crypto.DecryptedPayload;
import dev.neuralabs.auth.crypto.E2EEDecryptionService.E2EEException;
import dev.neuralabs.auth.crypto.E2EEDecryptionService;
import dev.neuralabs.auth.crypto.E2EEResponseEncryption.E2EEEncryptionException;
import dev.neuralabs.auth.crypto.E2EEResponseEncryption;
import dev.neuralabs.auth.crypto.KeyEncryptionService;
import dev.neuralabs.auth.database.DatabaseConnection;
import dev.neuralabs.auth.database.DatabaseInterface;
import dev.neuralabs.auth.model.AuditLog;
import dev.neuralabs.auth.model.License;
import dev.neuralabs.auth.model.Plugin;
import dev.neuralabs.auth.model.Session;
import dev.neuralabs.auth.security.RateLimiter;
import dev.neuralabs.auth.service.DockerEncryptionService;
import dev.neuralabs.auth.util.GsonUtil;
import dev.neuralabs.auth.util.JWTUtil;
import dev.neuralabs.auth.websocket.EncryptionWebSocketHandler;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import spark.Request;
import spark.Response;

import javax.servlet.MultipartConfigElement;
import javax.servlet.http.Part;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.*;

@Slf4j
public class PluginController {
  private final DatabaseInterface database;
  private final Gson gson;
  private final DockerEncryptionService dockerService;
  private final EncryptionWebSocketHandler webSocketHandler;
  private final KeyEncryptionService keyEncryptionService;
  private final E2EEDecryptionService e2eeService;
  private final E2EEResponseEncryption responseEncryption;

  private final RateLimiter metadataRateLimiter;

  public PluginController(
      KeyEncryptionService keyEncryptionService,
      E2EEDecryptionService e2eeService,
      E2EEResponseEncryption responseEncryption) {
    this.database = DatabaseConnection.getInstance().getDatabase();
    this.gson = GsonUtil.buildApi();
    this.dockerService = new DockerEncryptionService();
    this.webSocketHandler = new EncryptionWebSocketHandler(8081);
    this.keyEncryptionService = keyEncryptionService;
    this.e2eeService = e2eeService;
    this.responseEncryption = responseEncryption;

    this.metadataRateLimiter = RateLimiter.Factory.forMetadataRequests();

    new Thread(() -> {
      try {
        webSocketHandler.start();
        log.info("WebSocket server started on port 8081");
      } catch (Exception e) {
        log.error("Failed to start WebSocket server", e);
      }
    }).start();
  }

  public String registerPlugin(Request request, Response response) {
    try {
      RegisterPluginRequest registerRequest;
      String jarFilePath = null;
      Path pluginsDir = Paths.get("/app/plugins");

      String contentType = request.contentType();
      if (contentType != null && contentType.startsWith("multipart/form-data")) {
        request.attribute("org.eclipse.jetty.multipartConfig", new MultipartConfigElement("/temp"));

        String pluginDataJson = request.queryParams("pluginData");
        if (pluginDataJson == null) {
          return error(response, 400, "Plugin data is required");
        }

        registerRequest = gson.fromJson(pluginDataJson, RegisterPluginRequest.class);
        if (registerRequest == null || !isValidPluginId(registerRequest.getPluginId())) {
          return error(response, 400, "Invalid plugin ID");
        }

        try {
          Part jarFilePart = request.raw().getPart("jarFile");
          if (jarFilePart != null && jarFilePart.getSize() > 0) {
            Files.createDirectories(pluginsDir);

            String fileName = registerRequest.getPluginId() + ".jar";
            Path jarFile = pluginsDir.resolve(fileName);

            try (InputStream inputStream = jarFilePart.getInputStream()) {
              Files.copy(inputStream, jarFile, StandardCopyOption.REPLACE_EXISTING);
              jarFilePath = jarFile.toString();
              log.info("JAR file uploaded successfully: {}", jarFilePath);
            }
          }
        } catch (Exception e) {
          log.warn("Failed to process JAR file upload: {}", e.getMessage());
        }
      } else {
        registerRequest = gson.fromJson(request.body(), RegisterPluginRequest.class);
      }

      if (registerRequest == null || !isValidPluginId(registerRequest.getPluginId()) ||
          registerRequest.getOriginalMainClass() == null) {
        return error(response, 400, "Valid plugin ID and original main class are required");
      }

      Plugin existingPlugin = database.findPluginById(registerRequest.getPluginId());
      if (existingPlugin != null) {
        return error(response, 409, "Plugin already exists");
      }

      Plugin plugin = Plugin.builder()
          .pluginId(registerRequest.getPluginId())
          .name(registerRequest.getName())
          .version(registerRequest.getVersion())
          .description(registerRequest.getDescription())
          .originalMainClass(registerRequest.getOriginalMainClass())
          .encryptionKey(null)
          .ownerId(registerRequest.getOwnerId())
          .active(true)
          .createdAt(Date.from(Instant.now()))
          .updatedAt(Date.from(Instant.now()))
          .jarHash(registerRequest.getJarHash())
          .targetPackages(registerRequest.getTargetPackages())
          .build();

      if (registerRequest.getEncryptionKey() != null && !registerRequest.getEncryptionKey().isEmpty()) {
        plugin.setEncryptionKey(keyEncryptionService.wrapKeyIfPresent(registerRequest.getEncryptionKey()));
      }

      database.savePlugin(plugin);

      String message = "Plugin registered successfully";
      if (jarFilePath != null) {
        message += " with JAR file uploaded";
      }

      logAuditEvent("PLUGIN_REGISTERED", null, request.ip(), true,
          "Plugin registered: " + registerRequest.getPluginId() +
              (jarFilePath != null ? " (with JAR file)" : ""));

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("pluginId", plugin.getPluginId());
      responseData.put("message", message);
      responseData.put("jarUploaded", jarFilePath != null);

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error registering plugin", e);
      return error(response, 500, "Internal server error: " + e.getMessage());
    }
  }

  public String getPluginMetadata(Request request, Response response) {
    try {
      if (!isE2EEReady()) {
        return error(response, 503, "E2EE service not available");
      }

      String requestBody = request.body();
      if (!isEncryptedPayload(requestBody)) {
        return error(response, 415, "Encrypted payload required");
      }

      DecryptedPayload payload;
      try {
        payload = e2eeService.decryptRequest(requestBody);
      } catch (E2EEException e) {
        log.warn("Failed to decrypt metadata request: {}", e.getMessage());
        return error(response, 400, "Failed to decrypt request");
      }
      MetadataRequest metadataRequest = gson.fromJson(payload.getData(), MetadataRequest.class);

      if (metadataRequest == null || metadataRequest.getLicenseKey() == null) {
        return error(response, 400, "License key is required");
      }

      String sessionToken = metadataRequest.getSessionToken();
      if (sessionToken == null || sessionToken.isEmpty()) {
        return error(response, 401, "Session token is required");
      }

      Session session = database.findSessionByToken(sessionToken);
      if (session == null || !session.isValid()) {
        logAuditEvent("METADATA_REQUEST_DENIED", metadataRequest.getLicenseKey(),
            request.ip(), false, "Invalid or expired session token");
        return error(response, 401, "Invalid or expired session");
      }

      if (session.getHardwareFingerprint() == null
          || !session.getHardwareFingerprint().equals(metadataRequest.getHardwareFingerprint())) {
        logAuditEvent("METADATA_REQUEST_DENIED", metadataRequest.getLicenseKey(),
            request.ip(), false, "Session hardware fingerprint mismatch");
        return error(response, 403, "Session/hardware mismatch");
      }

      if (!session.getLicenseKey().equals(metadataRequest.getLicenseKey())) {
        logAuditEvent("METADATA_REQUEST_DENIED", metadataRequest.getLicenseKey(),
            request.ip(), false, "Session token does not match license");
        return error(response, 403, "Session/license mismatch");
      }

      String licenseKey = metadataRequest.getLicenseKey();
      if (!metadataRateLimiter.tryConsume(licenseKey)) {
        log.warn("Metadata rate limit exceeded for license: {}", maskLicenseKey(licenseKey));
        response.status(429);
        return gson.toJson(Map.of(
            "success", false,
            "error", "Too many metadata requests. Please try again later.",
            "retryAfter", 120
        ));
      }

      License license = database.findLicenseByKey(licenseKey);
      if (license == null || !license.canBeUsed()) {
        logAuditEvent("METADATA_REQUEST_DENIED", metadataRequest.getLicenseKey(),
            request.ip(), false, "Invalid or inactive license");
        return error(response, 403, "Invalid or inactive license");
      }

      Plugin plugin = database.findPluginById(license.getPluginId());
      if (plugin == null || !plugin.canBeUsed()) {
        logAuditEvent("METADATA_REQUEST_DENIED", metadataRequest.getLicenseKey(),
            request.ip(), false, "Plugin not found or inactive");
        return error(response, 404, "Plugin not found or inactive");
      }

      String encryptionKey = unwrapEncryptionKey(license.getEncryptionKey());
      if (encryptionKey == null && plugin.getEncryptionKey() != null) {
        encryptionKey = unwrapEncryptionKey(plugin.getEncryptionKey());
      }
      if (encryptionKey == null) {
        return error(response, 409, "Encryption key not provisioned for license");
      }

      logAuditEvent("METADATA_REQUEST_SUCCESS", metadataRequest.getLicenseKey(),
          request.ip(), true, "Plugin metadata delivered: " + plugin.getPluginId());

      List<String> targetPackages = license.getTargetPackages();
      if (targetPackages == null || targetPackages.isEmpty()) {
        targetPackages = plugin.getTargetPackages();
      }

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("pluginId", plugin.getPluginId());
      responseData.put("encryptionKey", encryptionKey);
      responseData.put("originalMainClass", plugin.getOriginalMainClass());
      responseData.put("pluginName", plugin.getName());
      responseData.put("pluginVersion", plugin.getVersion());
      responseData.put("targetPackages", targetPackages);

      try {
        return responseEncryption.encryptResponse(responseData, payload);
      } catch (E2EEEncryptionException e) {
        log.error("Failed to encrypt metadata response", e);
        return error(response, 500, "Failed to encrypt response");
      }
    } catch (Exception e) {
      log.error("Error getting plugin metadata", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String listPlugins(Request request, Response response) {
    try {
      List<Plugin> plugins = database.findAllPlugins();

      List<Map<String, Object>> sanitizedPlugins = new ArrayList<>();
      for (Plugin plugin : plugins) {
        Map<String, Object> sanitized = new HashMap<>();
        sanitized.put("pluginId", plugin.getPluginId());
        sanitized.put("name", plugin.getName());
        sanitized.put("version", plugin.getVersion());
        sanitized.put("description", plugin.getDescription());
        sanitized.put("active", plugin.isActive());
        sanitized.put("createdAt", plugin.getCreatedAt());
        sanitized.put("updatedAt", plugin.getUpdatedAt());
        sanitized.put("targetPackages", plugin.getTargetPackages());
        sanitized.put("ownerId", plugin.getOwnerId());
        sanitizedPlugins.add(sanitized);
      }

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("plugins", sanitizedPlugins);
      responseData.put("total", plugins.size());

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error listing plugins", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String updatePlugin(Request request, Response response) {
    try {
      String pluginId = request.params(":id");
      Plugin existingPlugin = database.findPluginById(pluginId);

      if (existingPlugin == null) {
        return error(response, 404, "Plugin not found");
      }

      RegisterPluginRequest updateRequest = gson.fromJson(request.body(), RegisterPluginRequest.class);

      existingPlugin.setName(updateRequest.getName());
      existingPlugin.setVersion(updateRequest.getVersion());
      existingPlugin.setDescription(updateRequest.getDescription());
      if (updateRequest.getOriginalMainClass() != null && !updateRequest.getOriginalMainClass().isBlank()) {
        existingPlugin.setOriginalMainClass(updateRequest.getOriginalMainClass());
      }
      String updatedEncryptionKey = updateRequest.getEncryptionKey();
      if (updatedEncryptionKey != null && !updatedEncryptionKey.isEmpty()) {
        existingPlugin.setEncryptionKey(keyEncryptionService.wrapKey(updatedEncryptionKey));
      }
      existingPlugin.setOwnerId(updateRequest.getOwnerId());
      if (updateRequest.getJarHash() != null && !updateRequest.getJarHash().isBlank()) {
        existingPlugin.setJarHash(updateRequest.getJarHash());
      }
      existingPlugin.setUpdatedAt(Date.from(Instant.now()));

      database.savePlugin(existingPlugin);

      logAuditEvent("PLUGIN_UPDATED", null, request.ip(), true,
          "Plugin updated: " + pluginId);

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("plugin", existingPlugin);
      responseData.put("message", "Plugin updated successfully");

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error updating plugin", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String deletePlugin(Request request, Response response) {
    try {
      String pluginId = request.params(":id");
      Plugin plugin = database.findPluginById(pluginId);

      if (plugin == null) {
        return error(response, 404, "Plugin not found");
      }

      database.deletePlugin(pluginId);

      logAuditEvent("PLUGIN_DELETED", null, request.ip(), true,
          "Plugin deleted: " + pluginId);

      return gson.toJson(Map.of("success", true, "message", "Plugin deleted successfully"));
    } catch (Exception e) {
      log.error("Error deleting plugin", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String getPlugin(Request request, Response response) {
    try {
      String pluginId = request.params(":id");
      Plugin plugin = database.findPluginById(pluginId);

      if (plugin == null) {
        return error(response, 404, "Plugin not found");
      }

      Map<String, Object> sanitized = new HashMap<>();
      sanitized.put("pluginId", plugin.getPluginId());
      sanitized.put("name", plugin.getName());
      sanitized.put("version", plugin.getVersion());
      sanitized.put("description", plugin.getDescription());
      sanitized.put("active", plugin.isActive());
      sanitized.put("createdAt", plugin.getCreatedAt());
      sanitized.put("updatedAt", plugin.getUpdatedAt());
      sanitized.put("ownerId", plugin.getOwnerId());

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("plugin", sanitized);

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error getting plugin", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String downloadProtectedPlugin(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = bearerClaims(request);
      if (claims == null) {
        response.status(401);
        return gson.toJson(Map.of("success", false, "error", "Unauthorized access"));
      }

      String pluginId = request.params(":pluginId");

      Plugin plugin = database.findPluginById(pluginId);
      if (plugin == null || !plugin.isActive()) {
        response.status(404);
        return gson.toJson(Map.of("success", false, "error", "Plugin not found or inactive"));
      }

      List<License> allLicenses = database.findAllLicenses();
      License userLicense = null;
      String userEmail = claims.getEmail();

      for (License license : allLicenses) {
        if (pluginId.equals(license.getPluginId()) &&
            userEmail.equalsIgnoreCase(license.getCustomerEmail()) &&
            license.canBeUsed()) {
          userLicense = license;
          break;
        }
      }

      if (userLicense == null) {
        response.status(403);
        return gson.toJson(Map.of("success", false, "error", "You do not have a valid license for this plugin"));
      }

      Map<String, Object> downloadMetadata = userLicense.getEncryptionMetadata();
      if (downloadMetadata == null) {
        downloadMetadata = new HashMap<>();
      }
      downloadMetadata.put("lastDownloadAt", Date.from(Instant.now()));
      downloadMetadata.put("downloadCount",
          (Integer) downloadMetadata.getOrDefault("downloadCount", 0) + 1);
      downloadMetadata.put("lastDownloadIp", request.ip());

      userLicense.setEncryptionMetadata(downloadMetadata);
      userLicense.setUpdatedAt(Date.from(Instant.now()));
      database.saveLicense(userLicense);

      logAuditEvent("PLUGIN_DOWNLOAD_REQUEST", userLicense.getLicenseKey(), request.ip(), true,
          "Plugin download requested: " + pluginId + " by user: " + claims.getUserId());

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("pluginId", pluginId);
      responseData.put("licenseKey", userLicense.getLicenseKey());
      responseData.put("downloadUrl", "/api/v1/plugins/" + pluginId + "/download/" + userLicense.getLicenseKey());
      responseData.put("message", "Plugin listo para descarga");
      responseData.put("encrypted", userLicense.getEncryptionKey() != null);

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error downloading plugin", e);
      response.status(500);
      return gson.toJson(Map.of("success", false, "error", "Internal server error"));
    }
  }

  public String getAvailablePlugins(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = bearerClaims(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      log.info("User {} requesting available plugins", claims.getUserId());

      List<Plugin> allPlugins = database.findAllPlugins();
      log.info("Total plugins en base de datos: {}", allPlugins.size());

      List<License> userLicenses = new ArrayList<>();
      String userEmail = claims.getEmail();

      if (claims.isAdmin()) {
        List<License> allLicenses = database.findAllLicenses();
        userLicenses = allLicenses;
      } else {
        List<License> allLicenses = database.findAllLicenses();
        for (License license : allLicenses) {
          if (userEmail.equalsIgnoreCase(license.getCustomerEmail()) && license.canBeUsed()) {
            userLicenses.add(license);
          }
        }
      }

      log.info("User {} has {} valid licenses", claims.getUserId(), userLicenses.size());

      List<Map<String, Object>> availablePlugins = new ArrayList<>();

      for (Plugin plugin : allPlugins) {
        if (!plugin.isActive())
          continue;

        boolean hasLicense = false;
        License userLicenseForPlugin = null;

        for (License license : userLicenses) {
          if (plugin.getPluginId().equals(license.getPluginId())) {
            hasLicense = true;
            userLicenseForPlugin = license;
            break;
          }
        }

        if (!hasLicense && !claims.isAdmin()) {
          continue;
        }

        Map<String, Object> pluginInfo = new HashMap<>();
        pluginInfo.put("pluginId", plugin.getPluginId());
        pluginInfo.put("name", plugin.getName());
        pluginInfo.put("version", plugin.getVersion());
        pluginInfo.put("description", plugin.getDescription());
        pluginInfo.put("ownerId", plugin.getOwnerId());
        pluginInfo.put("createdAt", plugin.getCreatedAt());
        pluginInfo.put("updatedAt", plugin.getUpdatedAt());
        pluginInfo.put("hasLicense", hasLicense);
        pluginInfo.put("targetPackages", plugin.getTargetPackages());

        if (userLicenseForPlugin != null) {
          pluginInfo.put("licenseKey", userLicenseForPlugin.getLicenseKey());
          pluginInfo.put("licenseType", userLicenseForPlugin.getLicenseType());
          pluginInfo.put("expiresAt", userLicenseForPlugin.getExpiresAt());
          pluginInfo.put("encrypted", userLicenseForPlugin.getEncryptionKey() != null);
        }

        if (claims.isAdmin()) {
          pluginInfo.put("originalMainClass", plugin.getOriginalMainClass());

          pluginInfo.put("jarHash", plugin.getJarHash());
        }

        availablePlugins.add(pluginInfo);
      }

      logAuditEvent("PLUGINS_AVAILABLE_REQUEST", null, request.ip(), true,
          "Available plugins requested by: " + claims.getUserId() + " (Admin: " + claims.isAdmin()
              + ")");

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("plugins", availablePlugins);
      responseData.put("total", availablePlugins.size());
      responseData.put("userRole", claims.getRole());

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error fetching available plugins", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String encryptPluginRealTime(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = bearerClaims(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      String pluginId = request.params(":pluginId");

      Plugin plugin = database.findPluginById(pluginId);
      if (plugin == null || !plugin.isActive()) {
        return error(response, 404, "Plugin not found or inactive");
      }

      List<String> targetPackages = plugin.getTargetPackages();
      if (targetPackages == null || targetPackages.isEmpty()) {
        return error(response, 400, "No hay paquetes objetivo definidos para este plugin");
      }

      List<License> allLicenses = database.findAllLicenses();
      License userLicense = null;
      String userEmail = claims.getEmail();

      for (License license : allLicenses) {
        if (pluginId.equals(license.getPluginId()) &&
            userEmail.equalsIgnoreCase(license.getCustomerEmail()) &&
            license.canBeUsed()) {
          userLicense = license;
          break;
        }
      }

      if (userLicense == null) {
        return error(response, 403, "You do not have a valid license for this plugin");
      }

      String sessionId = UUID.randomUUID().toString();

      userLicense.setTargetPackages(targetPackages);
      userLicense.setUpdatedAt(Date.from(Instant.now()));

      Map<String, Object> encryptionMetadata = new HashMap<>();
      encryptionMetadata.put("configuredAt", Date.from(Instant.now()));
      encryptionMetadata.put("configuredBy", claims.getUserId());
      encryptionMetadata.put("packageCount", targetPackages.size());
      encryptionMetadata.put("originalPlugin", pluginId);
      encryptionMetadata.put("sessionId", sessionId);
      userLicense.setEncryptionMetadata(encryptionMetadata);

      database.saveLicense(userLicense);

      logAuditEvent("PLUGIN_ENCRYPTION_CONFIGURED", userLicense.getLicenseKey(), request.ip(), true,
          "Encryption configured for plugin: " + pluginId + " with packages: " + targetPackages);

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("pluginId", pluginId);
      responseData.put("licenseKey", userLicense.getLicenseKey());
      responseData.put("targetPackages", targetPackages);
      responseData.put("encryptionMetadata", encryptionMetadata);
      responseData.put("sessionId", sessionId);
      responseData.put("message",
          "Plugin configured for encryption. The key will be generated during the encryption process.");

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error in real-time encryption", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String startDockerEncryption(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = bearerClaims(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      String pluginId = request.params(":pluginId");
      String sessionId = request.queryParams("sessionId");

      if (sessionId == null || sessionId.isEmpty()) {
        return error(response, 400, "Session ID required");
      }

      Plugin plugin = database.findPluginById(pluginId);
      if (plugin == null || !plugin.isActive()) {
        return error(response, 404, "Plugin not found or inactive");
      }

      List<License> allLicenses = database.findAllLicenses();
      License tempLicense = null;
      String userEmail = claims.getEmail();

      for (License license : allLicenses) {
        if (pluginId.equals(license.getPluginId()) &&
            userEmail.equalsIgnoreCase(license.getCustomerEmail()) &&
            license.canBeUsed()) {
          tempLicense = license;
          break;
        }
      }

      final License userLicense = tempLicense;

      if (userLicense == null) {
        return error(response, 403, "You do not have a valid license for this plugin");
      }

      if (userLicense.getTargetPackages() == null || userLicense.getTargetPackages().isEmpty()) {
        return error(response, 400, "No packages configured for encryption");
      }

      String inputJarPath = "/app/plugins/" + pluginId + ".jar";

      dockerService.encryptPlugin(
              pluginId,
              userLicense.getLicenseKey(),
              userLicense.getTargetPackages(),
              inputJarPath,
              logMessage -> webSocketHandler.sendLogToSession(sessionId, logMessage, "info"),
              (percent, progressMessage) -> webSocketHandler.sendProgressToSession(sessionId, percent))
          .thenAccept(result -> {
            if (result.isSuccess()) {
              try {
                if (result.getEncryptionKey() != null) {
                  String wrappedKey = keyEncryptionService.wrapKeyIfPresent(result.getEncryptionKey());
                  userLicense.setEncryptionKey(wrappedKey);
                  log.info("Stored wrapped encryption key for license {}", maskLicenseKey(userLicense.getLicenseKey()));
                }

                Map<String, Object> meta = userLicense.getEncryptionMetadata();
                if (meta == null)
                  meta = new HashMap<>();
                if (result.getEncryptionId() != null) {
                  meta.put("encryptionId", result.getEncryptionId());
                }
                if (result.getSignature() != null) {
                  meta.put("signature", result.getSignature());
                }
                userLicense.setEncryptionMetadata(meta);
                userLicense.setUpdatedAt(Date.from(Instant.now()));
                database.saveLicense(userLicense);
              } catch (Exception e) {
                log.warn("Failed to persist encryption data into license metadata: {}", e.getMessage());
              }

              webSocketHandler.sendCompletionToSession(
                  sessionId,
                  true,
                  "/api/v1/plugins/" + pluginId + "/download/" + userLicense.getLicenseKey(),
                  result.getEncryptionId(),
                  pluginId,
                  plugin.getVersion());

              logAuditEvent("PLUGIN_ENCRYPTION_COMPLETED", userLicense.getLicenseKey(),
                  request.ip(), true, "Plugin encrypted successfully: " + pluginId);
            } else {
              String errorMessage = result.getMessage();
              if (errorMessage.contains("Docker") || errorMessage.contains("docker") ||
                  errorMessage.contains("SocketException")
                  || errorMessage.contains("Connection refused")) {
                webSocketHandler.sendDockerErrorToSession(sessionId, errorMessage);
              } else {
                webSocketHandler.sendCompletionToSession(sessionId, false, null, null, pluginId,
                    plugin.getVersion());
              }

              logAuditEvent("PLUGIN_ENCRYPTION_FAILED", userLicense.getLicenseKey(),
                  request.ip(), false, "Error encrypting plugin: " + errorMessage);
            }
          }).exceptionally(throwable -> {
            String errorMessage = throwable.getMessage();
            log.error("Exception during plugin encryption", throwable);

            if (errorMessage.contains("Docker") || errorMessage.contains("docker") ||
                errorMessage.contains("SocketException")
                || errorMessage.contains("Connection refused")) {
              webSocketHandler.sendDockerErrorToSession(sessionId, errorMessage);
            } else {
              webSocketHandler.sendLogToSession(sessionId, "Encryption failed: " + errorMessage, "error");
              webSocketHandler.sendCompletionToSession(sessionId, false, null);
            }

            logAuditEvent("PLUGIN_ENCRYPTION_EXCEPTION", userLicense.getLicenseKey(),
                request.ip(), false, "Exception during encryption: " + errorMessage);

            return null;
          });

      return gson.toJson(Map.of("success", true, "message", "Encryption started", "sessionId", sessionId));
    } catch (Exception e) {
      log.error("Error starting Docker encryption", e);
      return error(response, 500, "Internal server error");
    }
  }

  public Object downloadEncryptedPlugin(Request request, Response response) {
    try {
      String pluginId = request.params(":pluginId");
      String licenseKey = request.params(":licenseKey");

      JWTUtil.JWTClaims claims = bearerClaims(request);
      License license = database.findLicenseByKey(licenseKey);
      if (license == null || !license.canBeUsed() || !pluginId.equals(license.getPluginId())
          || claims == null
          || (!claims.isAdmin() && !claims.getEmail().equalsIgnoreCase(license.getCustomerEmail()))) {
        response.status(403);
        return gson.toJson(Map.of("success", false, "error", "Invalid license for this plugin"));
      }

      Plugin plugin = database.findPluginById(pluginId);
      if (plugin == null || !plugin.isActive()) {
        response.status(404);
        return gson.toJson(Map.of("success", false, "error", "Plugin not found or inactive"));
      }

      if (license.getEncryptionKey() == null || license.getTargetPackages() == null) {
        response.status(400);
        return gson
            .toJson(Map.of("success", false, "error", "Plugin not encrypted yet. Please encrypt first."));
      }

      logAuditEvent("ENCRYPTED_PLUGIN_DOWNLOAD", licenseKey, request.ip(), true,
          "Encrypted plugin downloaded: " + pluginId);

      String encryptedJarPath = findEncryptedJarFile(pluginId, licenseKey);
      if (encryptedJarPath == null) {
        response.status(404);
        return gson.toJson(Map.of("success", false, "error", "Encrypted plugin not available"));
      }

      response.type("application/java-archive");
      String pluginName = plugin.getName() != null ? plugin.getName() : pluginId;
      pluginName = pluginName.toLowerCase().replaceAll("[^a-z0-9.-]", "-").replaceAll("-+", "-");
      String version = plugin.getVersion() != null ? plugin.getVersion() : "v" + System.currentTimeMillis();
      String encryptionId = null;
      if (license.getEncryptionMetadata() != null) {
        Object eid = license.getEncryptionMetadata().get("encryptionId");
        if (eid != null)
          encryptionId = String.valueOf(eid);
      }
      if (encryptionId == null) {
        encryptionId = license.getLicenseKey().length() > 8 ? license.getLicenseKey().substring(0, 8)
            : license.getLicenseKey();
      }
      String fileName = String.format("%s-%s-encrypted-%s.jar", pluginName, version, encryptionId);
      response.header("Content-Disposition", "attachment; filename=\"" + fileName + "\"");

      byte[] jarContent = Files.readAllBytes(Paths.get(encryptedJarPath));
      response.header("Content-Length", String.valueOf(jarContent.length));
      return jarContent;
    } catch (Exception e) {
      log.error("Error downloading encrypted plugin", e);
      response.status(500);
      response.type("application/json");
      return gson.toJson(Map.of("success", false, "error", "Internal server error"));
    }
  }

  private String findEncryptedJarFile(String pluginId, String licenseKey) {
    String[] possiblePaths = {
        "/tmp/nebeniac-encryption/" + pluginId + "_" + licenseKey + "/output/plugin-encrypted.jar",
        "/app/encrypted/" + pluginId + "_" + licenseKey + ".jar",
        "/var/lib/nebeniac/encrypted/" + pluginId + "-" + licenseKey.substring(0, 8) + ".jar",
        System.getProperty("java.io.tmpdir") + "/nebeniac-encryption/" + pluginId
            + "/output/plugin-encrypted.jar"
    };

    for (String path : possiblePaths) {
      try {
        if (Files.exists(Paths.get(path))) {
          log.info("Found encrypted JAR at: " + path);
          return path;
        }
      } catch (Exception e) {
        log.debug("Could not check path: " + path, e);
      }
    }

    log.warn("No encrypted JAR found for plugin: " + pluginId + ", license: " + licenseKey.substring(0, 8) + "...");
    return null;
  }

  private void logAuditEvent(String event, String licenseKey, String clientIp,
                             boolean success, String message) {
    try {
      AuditLog auditLog = AuditLog.builder()
          .timestamp(Date.from(Instant.now()))
          .level("INFO")
          .event(event)
          .licenseKey(licenseKey)
          .clientIp(clientIp)
          .success(success)
          .message(message)
          .build();

      database.saveAuditLog(auditLog);
    } catch (Exception e) {
      log.error("Error saving audit log", e);
    }
  }

  @Getter
  @Setter
  public static class RegisterPluginRequest {
    private String pluginId;
    private String name;
    private String version;
    private String description;
    private String originalMainClass;
    private String encryptionKey;
    private String ownerId;
    private String jarHash;
    private List<String> targetPackages;
  }

  @Getter
  @Setter
  public static class MetadataRequest {
    private String licenseKey;
    private String hardwareFingerprint;
    private String sessionToken;
  }

  private static boolean isValidPluginId(String pluginId) {
    return pluginId != null && pluginId.matches("[A-Za-z0-9._-]{1,64}") && !pluginId.startsWith(".");
  }

  private boolean isE2EEReady() {
    return e2eeService != null && e2eeService.isReady() && responseEncryption != null;
  }

  private String unwrapEncryptionKey(String wrappedKey) {
    if (wrappedKey == null || wrappedKey.isEmpty()) {
      return null;
    }
    try {
      return keyEncryptionService.unwrapKey(wrappedKey);
    } catch (RuntimeException e) {
      log.error("Failed to unwrap encryption key: {}", e.getMessage());
      throw new IllegalStateException("Failed to unwrap encryption key", e);
    }
  }

  public String getSignaturePublicKey(Request request, Response response) {
    try {
      String publicKeyBase64Url = dockerService.getPublicKeyBase64Url();

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("publicKey", publicKeyBase64Url);
      responseData.put("algorithm", "Ed25519");
      responseData.put("format", "Base64URL");
      responseData.put("usage", "JAR signature verification");

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error getting signature public key", e);
      return error(response, 500, "Internal server error");
    }
  }
}
