package dev.neuralabs.protector;

import dev.neuralabs.protector.messaging.RabbitMQLogger;
import dev.neuralabs.protector.signature.JarSigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.util.Base64;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;

public class App {
  private static final Logger logger = LoggerFactory.getLogger(App.class);

  public static void main(String[] args) {
    logger.info("Starting NebeniacProtector...");

    if (args.length < 2) {
      logger.error("Usage:");
      logger.error("  Legacy mode: java -jar NebeniacProtector.jar <input_jar> <output_jar>");
      logger.error(
          "  License mode: java -jar NebeniacProtector.jar <input_jar> <output_jar> <licenseKey> <pluginId>");
      logger.error(
          "  License mode with packages: java -jar NebeniacProtector.jar <input_jar> <output_jar> <licenseKey> <pluginId> <package1,package2,...>");
      return;
    }

    String inputJarPathStr = args[0];
    String outputJarPathStr = args[1];
    String licenseKey = null;
    String pluginId = null;
    List<String> targetPackages = null;
    String perLicenseSalt = null;
    String sessionId = null;

    if (args.length >= 4) {
      licenseKey = args[2];
      pluginId = args[3];
      logger.info("License mode active - Plugin ID: {}", pluginId);

      if (args.length >= 5 && !args[4].isBlank()) {
        String packagesStr = args[4];
        targetPackages = Arrays.asList(packagesStr.split(","));
        logger.info("Target packages specified: {}", targetPackages);
      }

      if (args.length >= 6) {
        perLicenseSalt = args[5];
      }
    } else {
      logger.info("Legacy mode active - using random key");
    }

    if (args.length >= 7) {
      sessionId = args[6];
      logger.info("Session ID received: {}", sessionId);
    }

    if (licenseKey != null && (perLicenseSalt == null || perLicenseSalt.isBlank())) {
      logger.error("Per-license salt is required when license mode is enabled");
      return;
    }

    byte[] serverPepper = loadServerPepper();
    PrivateKey signingKey = loadSigningKey();

    if (sessionId == null) {
      sessionId = UUID.randomUUID().toString();
      logger.info("Session ID generado: {}", sessionId);
    }

    RabbitMQLogger rabbitLogger = new RabbitMQLogger(sessionId);
    rabbitLogger.info("NebeniacProtector started for session: " + sessionId);

    if (pluginId != null) {
      rabbitLogger.notifyStart(pluginId, licenseKey);
    }

    logger.info("Archivo de entrada: {}", inputJarPathStr);
    logger.info("Archivo de salida: {}", outputJarPathStr);
    rabbitLogger.info("Input JAR: " + inputJarPathStr);
    rabbitLogger.info("Output JAR: " + outputJarPathStr);

    try {
      JarProcessor jarProcessor;
      if (licenseKey != null && pluginId != null) {
        jarProcessor = new JarProcessor(Paths.get(inputJarPathStr), licenseKey, pluginId, targetPackages, perLicenseSalt, serverPepper);
      } else {
        jarProcessor = new JarProcessor(Paths.get(inputJarPathStr));
      }

      rabbitLogger.sendProgress(10, "Starting JAR analysis...");
      jarProcessor.loadAndAnalyzeAndEncryptJar();
      rabbitLogger.sendProgress(60, "JAR analysis and encryption completed");

      logger.info("Main class del plugin original: {}", jarProcessor.getMainClass());
      logger.info("Clases cifradas encontradas: {}", jarProcessor.getEncryptedClassEntries().size());
      logger.info("Recursos encontrados: {}", jarProcessor.getResourceEntries().size());
      rabbitLogger.info("JAR analysis completed");
      rabbitLogger.info("Main class: " + jarProcessor.getMainClass());
      rabbitLogger.info("Encrypted classes: " + jarProcessor.getEncryptedClassEntries().size());
      rabbitLogger.info("Resources: " + jarProcessor.getResourceEntries().size());

      rabbitLogger.sendProgress(65, "Writing protected JAR...");

      String encryptionId = "ENC-" + System.currentTimeMillis() + "-" + generateRandomString(8);
      rabbitLogger.info("Generated encryption ID: " + encryptionId);

      JarWriter jarWriter = new JarWriter(
          Paths.get(outputJarPathStr),
          jarProcessor.getMainClass(),
          jarProcessor.getEncryptedClassEntries(),
          jarProcessor.getResourceEntries(),
          jarProcessor.getPluginYmlContent(),
          jarProcessor.getEncryptionUtil().getEncryptionKeyBase64(),
          encryptionId,
          signingKey);

      AtomicReference<String> pluginIdRef = new AtomicReference<>(null);
      pluginIdRef.set(pluginId);
      AtomicReference<String> signatureRef = new AtomicReference<>(null);

      CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
        try {
          signatureRef.set(jarWriter.writeProtectedJar());
        } catch (IOException e) {
          throw new CompletionException(e);
        }
      }).thenRun(() -> {
        rabbitLogger.sendProgress(90, "Protected JAR written successfully");
        logger.info("Plugin protected successfully!");

        rabbitLogger.sendProgress(95, "Finalizing encryption process...");

        String safePluginId = pluginIdRef.get() != null ? pluginIdRef.get() : "unknown";
        String encryptionKeyBase64 = jarProcessor.getEncryptionUtil().getEncryptionKeyBase64();
        rabbitLogger.notifySuccess(safePluginId, outputJarPathStr, encryptionId, encryptionKeyBase64);
      });

      future.get();
    } catch (Exception e) {
      logger.error("An error occurred during the protection process", e);
      rabbitLogger.notifyError(pluginId != null ? pluginId : "unknown", e.getMessage());
    } finally {
      rabbitLogger.close();
    }
  }

  private static String generateRandomString(int length) {
    String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    StringBuilder result = new StringBuilder();
    Random random = new Random();
    for (int i = 0; i < length; i++) {
      result.append(chars.charAt(random.nextInt(chars.length())));
    }
    return result.toString();
  }

  private static byte[] loadServerPepper() {
    String pepperBase64 = System.getenv("NEBENIAC_SERVER_PEPPER");
    if (pepperBase64 == null || pepperBase64.isBlank()) {
      logger.warn("NEBENIAC_SERVER_PEPPER not provided - deriving keys without server pepper");
      return null;
    }
    try {
      return Base64.getDecoder().decode(pepperBase64.trim());
    } catch (IllegalArgumentException e) {
      logger.error("Invalid NEBENIAC_SERVER_PEPPER value: {}", e.getMessage());
      return null;
    }
  }

  private static PrivateKey loadSigningKey() {
    String privateKeyBase64 = System.getenv("NEBENIAC_SIGNING_PRIVATE_KEY");
    if (privateKeyBase64 == null || privateKeyBase64.isBlank()) {
      logger.warn("NEBENIAC_SIGNING_PRIVATE_KEY not provided - JARs will not be signed");
      return null;
    }
    try {
      return JarSigner.importPrivateKey(privateKeyBase64.trim());
    } catch (Exception e) {
      logger.error("Failed to load signing key: {}", e.getMessage());
      return null;
    }
  }

}
