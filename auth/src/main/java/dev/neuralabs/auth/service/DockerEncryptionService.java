package dev.neuralabs.auth.service;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientBuilder;
import dev.neuralabs.auth.messaging.RabbitMQLogListener;
import io.netty.handler.timeout.TimeoutException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

@Slf4j
public class DockerEncryptionService {
  private static final SecureRandom CONTENT_KEY_RANDOM = new SecureRandom();
  private final DockerClient dockerClient;
  private final String workspaceDir;
  private final RabbitMQLogListener rabbitMQListener;
  private final Ed25519SignatureService signatureService;
  private final JarSignatureService jarSignatureService;
  private final ConfigYmlUpdater configYmlUpdater;

  public DockerEncryptionService() {
    DefaultDockerClientConfig.Builder configBuilder = DefaultDockerClientConfig.createDefaultConfigBuilder();

    String os = System.getProperty("os.name").toLowerCase();
    String dockerHost = System.getProperty("docker.host");

    boolean isWSL = isRunningInWSL();
    boolean isInContainer = isRunningInContainer();

    if (dockerHost != null) {
      configBuilder.withDockerHost(dockerHost);
      if (dockerHost.startsWith("tcp://")) {
        configBuilder.withDockerTlsVerify(false);
      }
      log.info("Using explicit Docker host: {}", dockerHost);
    } else if (isInContainer) {
      Path dockerSock = Paths.get("/var/run/docker.sock");
      if (Files.exists(dockerSock)) {
        configBuilder.withDockerHost("unix:///var/run/docker.sock");
        log.info("Configuring Docker client for container environment with Unix socket");
      } else {
        configBuilder.withDockerHost("tcp://host.docker.internal:2375")
            .withDockerTlsVerify(false);
        log.info("Configuring Docker client for container environment with TCP fallback");
      }
    } else if (isWSL) {
      configBuilder.withDockerHost("tcp://localhost:2375")
          .withDockerTlsVerify(false);
      log.info("Configuring Docker client for WSL with Docker Desktop");
    } else if (os.contains("win")) {
      configBuilder.withDockerHost("tcp://localhost:2375")
          .withDockerTlsVerify(false);
      log.info("Configuring Docker client for Windows");
    } else if (os.contains("mac")) {
      configBuilder.withDockerHost("unix:///var/run/docker.sock");
      log.info("Configuring Docker client for macOS");
    } else {
      configBuilder.withDockerHost("unix:///var/run/docker.sock");
      log.info("Configuring Docker client for Linux");
    }

    DefaultDockerClientConfig config = configBuilder.build();
    this.dockerClient = DockerClientBuilder.getInstance(config).build();

    try {
      this.rabbitMQListener = new RabbitMQLogListener();
      log.info("RabbitMQ listener initialized successfully");
    } catch (Exception e) {
      log.warn("Failed to initialize RabbitMQ listener: {}", e.getMessage());
      throw new RuntimeException("Failed to initialize RabbitMQ listener", e);
    }

    try {
      this.signatureService = new Ed25519SignatureService();
      this.jarSignatureService = new JarSignatureService(signatureService);
      this.configYmlUpdater = new ConfigYmlUpdater();
      log.info("Ed25519 signature services initialized successfully");
      log.info("Public key (Base64URL): {}", signatureService.getPublicKeyBase64Url());
    } catch (Exception e) {
      log.error("Failed to initialize signature services: {}", e.getMessage());
      throw new RuntimeException("Failed to initialize signature services", e);
    }

    this.workspaceDir = System.getProperty("java.io.tmpdir") + File.separator + "nebeniac-encryption"
        + File.separator;

    try {
      Files.createDirectories(Paths.get(workspaceDir));
      log.info("Docker encryption service initialized with workspace: {}", workspaceDir);

      testDockerConnection();
    } catch (IOException e) {
      log.error("Failed to create workspace directory", e);
      throw new RuntimeException("Failed to initialize Docker encryption service", e);
    }
  }

  private void testDockerConnection() {
    try {
      dockerClient.pingCmd().exec();
      log.info("Docker connection test successful");
    } catch (Exception e) {
      log.error("Docker connection test failed. Make sure Docker is running and accessible.", e);

      String os = System.getProperty("os.name").toLowerCase();
      boolean isWSL = isRunningInWSL();
      String errorMessage = "Docker is not available. ";

      if (isWSL) {
        errorMessage += "WSL + Docker Desktop Setup Required:\n" +
            "1. Make sure Docker Desktop is running on Windows host\n" +
            "2. In Docker Desktop: Settings > General > 'Expose daemon on tcp://localhost:2375 without TLS'\n"
            +
            "3. In Docker Desktop: Settings > Resources > WSL Integration > Enable for your distro\n" +
            "4. In WSL: export DOCKER_HOST=tcp://localhost:2375\n" +
            "5. Test with: docker version";
        log.error("WSL Docker Configuration Required:");
        log.error("1. Enable Docker Desktop WSL integration");
        log.error("2. Enable TCP API on port 2375");
        log.error("3. Set DOCKER_HOST=tcp://localhost:2375 in WSL");
      } else if (os.contains("win")) {
        errorMessage += "Windows Setup Required:\n" +
            "1. Make sure Docker Desktop is running\n" +
            "2. Go to Docker Desktop Settings > General\n" +
            "3. Enable 'Expose daemon on tcp://localhost:2375 without TLS'\n" +
            "4. Apply & Restart Docker Desktop\n" +
            "5. Alternative: Set system property -Ddocker.host=npipe:////./pipe/docker_engine";
        log.error("Windows Docker Configuration Required:");
        log.error("1. Open Docker Desktop");
        log.error("2. Go to Settings > General");
        log.error("3. Check 'Expose daemon on tcp://localhost:2375 without TLS'");
        log.error("4. Apply & Restart Docker Desktop");
      } else {
        errorMessage += "Unix Setup Required:\n" +
            "1. Make sure Docker daemon is running: sudo systemctl start docker\n" +
            "2. Add user to docker group: sudo usermod -aG docker $USER\n" +
            "3. Restart terminal session or run: newgrp docker";
        log.error(
            "Unix users: Make sure Docker daemon is running and the current user has permission to access the Docker socket");
      }

      throw new RuntimeException(errorMessage, e);
    }
  }

  private boolean isRunningInWSL() {
    try {
      String wslDistroName = System.getenv("WSL_DISTRO_NAME");
      String wslInterop = System.getenv("WSL_INTEROP");

      if (wslDistroName != null || wslInterop != null) {
        log.info("Detected WSL environment: distro={}, interop={}", wslDistroName, wslInterop);
        return true;
      }

      Path procVersion = Paths.get("/proc/version");
      if (Files.exists(procVersion)) {
        String version = Files.readString(procVersion).toLowerCase();
        if (version.contains("microsoft") || version.contains("wsl")) {
          log.info("Detected WSL from /proc/version: {}", version);
          return true;
        }
      }

      return false;
    } catch (Exception e) {
      log.debug("Could not detect WSL environment", e);
      return false;
    }
  }

  private boolean isRunningInContainer() {
    try {
      if (Files.exists(Paths.get("/.dockerenv"))) {
        log.info("Detected container environment: /.dockerenv file exists");
        return true;
      }

      Path cgroupPath = Paths.get("/proc/1/cgroup");
      if (Files.exists(cgroupPath)) {
        String cgroup = Files.readString(cgroupPath).toLowerCase();
        if (cgroup.contains("docker") || cgroup.contains("containerd") || cgroup.contains("kubepods")) {
          log.info("Detected container environment from /proc/1/cgroup: {}",
              cgroup.substring(0, Math.min(100, cgroup.length())));
          return true;
        }
      }

      String hostname = System.getenv("HOSTNAME");
      if (hostname != null && (hostname.length() == 12 || hostname.matches("^[a-f0-9]{12}$"))) {
        log.info("Detected container environment: container-like hostname {}", hostname);
        return true;
      }

      return false;
    } catch (Exception e) {
      log.debug("Could not detect container environment", e);
      return false;
    }
  }

  public CompletableFuture<EncryptionResult> encryptPlugin(
      String pluginId,
      String licenseKey,
      List<String> targetPackages,
      String inputJarPath,
      Consumer<String> logCallback,
      BiConsumer<Integer, String> progressCallback) {
    return CompletableFuture.supplyAsync(() -> {
      String sessionId = UUID.randomUUID().toString();
      String sessionDir = workspaceDir + sessionId + "/";
      String containerOutputPath = "/app/temp/" + sessionId + "/plugin-encrypted.jar";
      String contentKey = generateContentKey();

      CompletableFuture<RabbitMQLogListener.CompletionMessage> completionFuture = new CompletableFuture<>();

      rabbitMQListener.listenForSession(sessionId,
          logCallback,
          (percent, message) -> {
            if (progressCallback != null) {
              progressCallback.accept(percent, message);
            }
            if (message != null && !message.isBlank()) {
              logCallback.accept(String.format("[PROGRESS] %d%% - %s", percent, message));
            } else {
              logCallback.accept(String.format("[PROGRESS] %d%%", percent));
            }
          },
          completion -> {
            log.info("Encryption completion received via RabbitMQ: success={}", completion.isSuccess());
            completionFuture.complete(completion);
          });

      try {
        logCallback.accept("[INFO] Starting encryption process for plugin: " + pluginId);
        logCallback.accept("[INFO] Session ID: " + sessionId);

        Files.createDirectories(Paths.get(sessionDir + "input"));
        Files.createDirectories(Paths.get(sessionDir + "output"));

        String packagesStr = String.join(",", targetPackages);
        logCallback.accept("[INFO] Using existing protector service container");

        String containerId = findProtectorContainer();
        if (containerId == null) {
          throw new RuntimeException(
              "Protector service container not found. Make sure docker-compose is running.");
        }

        logCallback.accept("[INFO] Found protector container: " + containerId.substring(0, 12));

        Path inputJar = Paths.get(inputJarPath);
        if (Files.exists(inputJar)) {
          Files.copy(inputJar, Paths.get(sessionDir + "input/plugin.jar"));
          logCallback.accept("[INFO] Copied input JAR to session workspace");
        } else {
          logCallback.accept("[WARNING] Input JAR not found at: " + inputJarPath);
          throw new RuntimeException("Input JAR not found: " + inputJarPath);
        }

        try {
          var mkdirExec = dockerClient.execCreateCmd(containerId)
              .withAttachStdout(true)
              .withAttachStderr(true)
              .withCmd("mkdir", "-p", "/app/temp/" + sessionId)
              .exec();
          dockerClient.execStartCmd(mkdirExec.getId())
              .exec(new ResultCallback.Adapter<Frame>())
              .awaitCompletion();
        } catch (Exception e) {
          logCallback.accept("[WARNING] Failed to ensure temp directory in container: " + e.getMessage());
        }

        String containerInputPath = "/app/temp/" + sessionId + "/plugin.jar";
        copyFileToContainer(containerId, sessionDir + "input/plugin.jar", containerInputPath, logCallback);

        logCallback.accept("[INFO] Starting encryption process...");
        logCallback.accept("[INFO] Waiting for RabbitMQ confirmation before considering process complete...");

        new Thread(() -> {
          try {
            int exitCode = executeEncryptionInContainer(containerId, sessionId, contentKey, containerOutputPath,
                licenseKey, pluginId, packagesStr,
                logCallback);
            logCallback.accept("[INFO] Processing completed with exit code: " + exitCode);
          } catch (Exception ex) {
            logCallback.accept("[ERROR] Exception launching encryption in container: " + ex.getMessage());
          }
        }).start();

        RabbitMQLogListener.CompletionMessage completion;
        try {
          completion = completionFuture.get(120, TimeUnit.SECONDS);
        } catch (TimeoutException e) {
          logCallback.accept("[ERROR] Timeout waiting for RabbitMQ completion message");
          return new EncryptionResult(false, null,
              "Timeout waiting for protector completion confirmation", null, null, null);
        } catch (Exception e) {
          logCallback.accept("[ERROR] Error waiting for RabbitMQ completion: " + e.getMessage());
          return new EncryptionResult(false, null,
              "Error waiting for protector completion: " + e.getMessage(), null, null, null);
        }

        if (!completion.isSuccess()) {
          logCallback.accept("[ERROR] RabbitMQ reported encryption failure: " + completion.getMessage());
          return new EncryptionResult(false, null, completion.getMessage(), completion.getEncryptionId(), null, completion.getSignature());
        }

        logCallback.accept("[INFO] RabbitMQ confirmation received, waiting for file to be fully written...");
        Thread.sleep(2000);

        copyFileFromContainer(containerId, containerOutputPath,
            sessionDir + "output/plugin-encrypted.jar", logCallback);

        Path encryptedJarPath = Paths.get(sessionDir + "output/plugin-encrypted.jar");
        if (!Files.exists(encryptedJarPath)) {
          logCallback.accept("[ERROR] Encrypted JAR not found after protector completion");
          return new EncryptionResult(false, null,
              "Encrypted JAR not found after protector completion", completion.getEncryptionId(), null, completion.getSignature());
        }

        long jarSize = Files.size(encryptedJarPath);
        if (jarSize <= 0) {
          logCallback.accept("[ERROR] Encrypted JAR is empty after extraction");
          return new EncryptionResult(false, null,
              "Encrypted JAR is empty after extraction", completion.getEncryptionId(), null, completion.getSignature());
        }

        logCallback.accept("[SUCCESS] Real encrypted JAR successfully extracted (" + jarSize + " bytes)");

        logCallback.accept("[INFO] Generating unique hardware fingerprint salt...");
        String hardwareFingerprintSalt = ConfigYmlUpdater.generateHardwareFingerprintSalt();
        logCallback.accept("[SUCCESS] Salt generated: " + hardwareFingerprintSalt.substring(0, Math.min(16, hardwareFingerprintSalt.length())) + "...");

        logCallback.accept("[INFO] Updating config.yml with signature key and salt...");
        String publicKeyBase64Url = signatureService.getPublicKeyBase64Url();
        try {
          configYmlUpdater.updateConfigInJar(encryptedJarPath, publicKeyBase64Url, hardwareFingerprintSalt);
          logCallback.accept("[SUCCESS] Config.yml updated successfully");
          logCallback.accept("[INFO] Signature public key: " + publicKeyBase64Url.substring(0, Math.min(32, publicKeyBase64Url.length())) + "...");
          logCallback.accept("[INFO] Hardware fingerprint salt: " + hardwareFingerprintSalt.substring(0, Math.min(16, hardwareFingerprintSalt.length())) + "...");
        } catch (Exception e) {
          logCallback.accept("[ERROR] Failed to update config.yml: " + e.getMessage());
          log.error("Failed to update config.yml in JAR", e);
          return new EncryptionResult(false, null,
              "Encryption succeeded but config.yml update failed: " + e.getMessage(),
              completion.getEncryptionId(), null, null);
        }

        logCallback.accept("[INFO] Signing encrypted JAR with Ed25519...");
        String jarSignature;
        try {
          jarSignature = jarSignatureService.signJar(encryptedJarPath);
          logCallback.accept("[SUCCESS] JAR signed successfully");
          logCallback.accept("[INFO] Signature (Base64URL): " + jarSignature.substring(0, Math.min(32, jarSignature.length())) + "...");
        } catch (Exception e) {
          logCallback.accept("[ERROR] Failed to sign JAR: " + e.getMessage());
          log.error("Failed to sign encrypted JAR", e);
          return new EncryptionResult(false, null,
              "Encryption succeeded but JAR signing failed: " + e.getMessage(),
              completion.getEncryptionId(), null, null);
        }

        String permanentDir = "/tmp/nebeniac-encryption/" + pluginId + "_" + licenseKey + "/output/";
        Files.createDirectories(Paths.get(permanentDir));
        Path permanentPath = Paths.get(permanentDir + "plugin-encrypted.jar");
        Files.copy(encryptedJarPath, permanentPath, StandardCopyOption.REPLACE_EXISTING);
        logCallback.accept("[INFO] Signed encrypted JAR saved to: " + permanentPath);

        String completionMessage = completion.getMessage() != null && !completion.getMessage().isBlank()
            ? completion.getMessage()
            : "Encryption and signing completed successfully";
        logCallback.accept("[SUCCESS] Encryption and signing process confirmed complete");

        String encryptionKey = contentKey;

        return new EncryptionResult(true, permanentPath.toString(), completionMessage,
            completion.getEncryptionId(), encryptionKey, jarSignature);
      } catch (Exception e) {
        log.error("Error during encryption process", e);
        logCallback.accept("[ERROR] Exception during encryption: " + e.getMessage());
        return new EncryptionResult(false, null, "Encryption failed: " + e.getMessage(), null, null, null);
      } finally {
        try {
          deleteDirectory(new File(sessionDir));
          logCallback.accept("[INFO] Cleanup completed");
        } catch (Exception e) {
          log.warn("Failed to cleanup session directory: " + sessionDir, e);
        }
      }
    });
  }

  private void deleteDirectory(File directory) {
    if (directory.exists()) {
      File[] files = directory.listFiles();
      if (files != null) {
        for (File file : files) {
          if (file.isDirectory()) {
            deleteDirectory(file);
          } else {
            file.delete();
          }
        }
      }
      directory.delete();
    }
  }

  @Getter
  @AllArgsConstructor
  public static class EncryptionResult {
    private final boolean success;
    private final String encryptedJarPath;
    private final String message;
    private final String encryptionId;
    private final String encryptionKey;
    private final String signature;
  }

  private void copyFileToContainer(String containerId, String hostPath, String containerPath,
                                   Consumer<String> logCallback) {
    try {
      dockerClient.copyArchiveToContainerCmd(containerId)
          .withHostResource(hostPath)
          .withRemotePath(containerPath.substring(0, containerPath.lastIndexOf('/')))
          .exec();

      logCallback.accept("[INFO] Copied " + hostPath + " to container:" + containerPath);
    } catch (Exception e) {
      logCallback.accept("[ERROR] Exception copying file to container: " + e.getMessage());
    }
  }

  private void copyFileFromContainer(String containerId, String containerPath, String hostPath,
                                     Consumer<String> logCallback) {
    try {
      try (var inputStream = dockerClient.copyArchiveFromContainerCmd(containerId, containerPath).exec()) {
        Path tempTarPath = Paths.get(hostPath + ".tar");
        Files.copy(inputStream, tempTarPath, StandardCopyOption.REPLACE_EXISTING);
        logCallback.accept("[INFO] Downloaded tar archive from container");

        extractJarFromTar(tempTarPath.toString(), hostPath, logCallback);

        Files.deleteIfExists(tempTarPath);
        logCallback.accept("[INFO] Extracted and cleaned up temporary files");
      }
    } catch (Exception e) {
      logCallback.accept("[ERROR] Exception copying file from container: " + e.getMessage());
    }
  }

  private void extractJarFromTar(String tarPath, String outputJarPath, Consumer<String> logCallback) {
    try {
      ProcessBuilder pb = new ProcessBuilder("tar", "-xf", tarPath, "-C",
          Paths.get(outputJarPath).getParent().toString());
      Process process = pb.start();
      int exitCode = process.waitFor();

      if (exitCode == 0) {
        String fileName = Paths.get(outputJarPath).getFileName().toString();
        Path extractedFile = Paths.get(outputJarPath).getParent().resolve(fileName);

        if (Files.exists(extractedFile)) {
          logCallback.accept("[INFO] Successfully extracted JAR file: " + outputJarPath);
        } else {
          logCallback.accept("[WARNING] JAR file not found after extraction, checking directory contents...");
          try (var files = Files.list(Paths.get(outputJarPath).getParent())) {
            files.forEach(file -> logCallback.accept("[INFO] Found file: " + file.getFileName()));
          }
        }
      } else {
        logCallback.accept("[ERROR] Failed to extract tar file (exit code: " + exitCode + ")");
      }
    } catch (Exception e) {
      logCallback.accept("[ERROR] Exception extracting tar file: " + e.getMessage());
    }
  }

  private String findProtectorContainer() {
    try {
      var containers = dockerClient.listContainersCmd()
          .withShowAll(false)
          .withNameFilter(List.of("nebeniac-protector"))
          .exec();

      if (!containers.isEmpty()) {
        return containers.get(0).getId();
      }
      return null;
    } catch (Exception e) {
      log.error("Failed to find protector container", e);
      return null;
    }
  }

  private int executeEncryptionInContainer(String containerId, String sessionId, String contentKey,
                                           String outputPath, String licenseKey, String pluginId,
                                           String targetPackages, Consumer<String> logCallback) {
    try {
      String[] findCommand = {"find", "/app", "-name", "NebeniacProtector*.jar", "-type", "f"};
      var findExecResponse = dockerClient.execCreateCmd(containerId)
          .withAttachStdout(true)
          .withAttachStderr(true)
          .withCmd(findCommand)
          .exec();

      dockerClient.execStartCmd(findExecResponse.getId())
          .exec(new ResultCallback.Adapter<Frame>())
          .awaitCompletion();

      String[] possibleJarPaths = {
          "/app/shared/protector.jar",
          "/app/target/protector-1.0-SNAPSHOT.jar",
          "/app/protector-1.0-SNAPSHOT.jar",
          "/app/protector.jar",
          "/app/shared/NebeniacProtector.jar",
          "/app/NebeniacProtector-1.0-SNAPSHOT.jar",
          "/app/target/NebeniacProtector-1.0-SNAPSHOT.jar",
          "/app/NebeniacProtector.jar"
      };

      String jarPath = null;
      for (String path : possibleJarPaths) {
        String[] testCommand = {"test", "-f", path};
        var testExecResponse = dockerClient.execCreateCmd(containerId)
            .withAttachStdout(true)
            .withAttachStderr(true)
            .withCmd(testCommand)
            .exec();

        dockerClient.execStartCmd(testExecResponse.getId())
            .exec(new ResultCallback.Adapter<Frame>())
            .awaitCompletion();

        var testInspectResponse = dockerClient.inspectExecCmd(testExecResponse.getId()).exec();
        Integer testExitCode = testInspectResponse.getExitCodeLong() != null
            ? testInspectResponse.getExitCodeLong().intValue()
            : 1;

        if (testExitCode == 0) {
          jarPath = path;
          logCallback.accept("[INFO] Found NebeniacProtector at: " + path);
          break;
        }
      }

      if (jarPath == null) {
        logCallback.accept("[ERROR] NebeniacProtector.jar not found in any expected location");
        return -1;
      }

      String inputPath = "/app/temp/" + sessionId + "/plugin.jar";

      String[] command = {
          "java", "-jar", jarPath,
          inputPath, outputPath,
          licenseKey, pluginId, targetPackages != null ? targetPackages : "", sessionId
      };

      logCallback.accept("[INFO] Executing encryption command in container...");

      var execCreateResponse = dockerClient.execCreateCmd(containerId)
          .withAttachStdout(true)
          .withAttachStderr(true)
          .withCmd(command)
          .withEnv(List.of("NEBENIAC_CONTENT_KEY=" + contentKey))
          .exec();

      dockerClient.execStartCmd(execCreateResponse.getId())
          .exec(new ResultCallback.Adapter<Frame>())
          .awaitCompletion();

      var execInspectResponse = dockerClient.inspectExecCmd(execCreateResponse.getId()).exec();
      Integer exitCode = execInspectResponse.getExitCodeLong() != null
          ? execInspectResponse.getExitCodeLong().intValue()
          : 0;

      logCallback.accept("[INFO] Encryption command completed with exit code: " + exitCode);
      return exitCode;
    } catch (Exception e) {
      logCallback.accept("[ERROR] Failed to execute encryption in container: " + e.getMessage());
      return -1;
    }
  }

  private static String generateContentKey() {
    byte[] key = new byte[32];
    CONTENT_KEY_RANDOM.nextBytes(key);
    try {
      return Base64.getEncoder().encodeToString(key);
    } finally {
      Arrays.fill(key, (byte) 0);
    }
  }

  public String getPublicKeyBase64Url() {
    return signatureService.getPublicKeyBase64Url();
  }
}
