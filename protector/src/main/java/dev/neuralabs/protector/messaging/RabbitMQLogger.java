package dev.neuralabs.protector.messaging;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeoutException;

@Slf4j
public class RabbitMQLogger implements AutoCloseable {
  private static final String EXCHANGE_NAME = "nebeniac.protector.logs";
  private static final String ROUTING_KEY_PREFIX = "protector.session.";

  private Connection connection;
  private Channel channel;
  private final String sessionId;
  private boolean enabled;

  public RabbitMQLogger(String sessionId) {
    this.sessionId = sessionId;
    this.enabled = initializeConnection();
  }

  private boolean initializeConnection() {
    try {
      String rabbitHost = System.getenv().getOrDefault("RABBITMQ_HOST", "localhost");
      int rabbitPort = Integer.parseInt(System.getenv().getOrDefault("RABBITMQ_PORT", "5672"));
      String rabbitUsername = System.getenv().getOrDefault("RABBITMQ_USERNAME", "nebeniac");
      String rabbitPassword = System.getenv().getOrDefault("RABBITMQ_PASSWORD", "tuputamadre02");

      ConnectionFactory factory = new ConnectionFactory();
      factory.setHost(rabbitHost);
      factory.setPort(rabbitPort);
      factory.setUsername(rabbitUsername);
      factory.setPassword(rabbitPassword);

      factory.setAutomaticRecoveryEnabled(true);
      factory.setNetworkRecoveryInterval(10000);

      log.info("Connecting to RabbitMQ at {}:{}...", rabbitHost, rabbitPort);
      connection = factory.newConnection();
      channel = connection.createChannel();

      channel.exchangeDeclare(EXCHANGE_NAME, "topic", true);

      log.info("RabbitMQ connection established for session: {}", sessionId);
      return true;
    } catch (Exception e) {
      log.warn("Failed to initialize RabbitMQ connection (logs will be local only): {}", e.getMessage());
      return false;
    }
  }

  public void sendLog(String level, String message) {
    if (!enabled) {
      return;
    }

    try {
      String logMessage = String.format(
          "{\"type\":\"LOG\",\"level\":\"%s\",\"message\":\"%s\",\"timestamp\":%d,\"sessionId\":\"%s\"}",
          level, escapeJson(message), System.currentTimeMillis(), sessionId);

      String routingKey = ROUTING_KEY_PREFIX + sessionId;
      channel.basicPublish(EXCHANGE_NAME, routingKey, null, logMessage.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      log.debug("Failed to send log to RabbitMQ: {}", e.getMessage());
      enabled = false;
    }
  }

  public void info(String message) {
    sendLog("INFO", message);
    log.info(message);
  }

  public void success(String message) {
    sendLog("SUCCESS", message);
    log.info("{}", message);
  }

  public void error(String message) {
    sendLog("ERROR", message);
    log.error(message);
  }

  public void warn(String message) {
    sendLog("WARN", message);
    log.warn(message);
  }

  public void notifyStart(String pluginId, String licenseKey) {
    info(String.format("Starting encryption process for plugin: %s (license: %s)", pluginId, licenseKey));
  }

  public void notifySuccess(String pluginId, String outputPath, String encryptionId) {
    success(String.format("Encryption completed successfully for plugin: %s", pluginId));
    sendProgress(100, "Encryption completed successfully");
    sendCompletion(true, outputPath, "Encryption completed successfully", encryptionId);
  }

  public void notifyError(String pluginId, String errorMessage) {
    error(String.format("Encryption failed for plugin: %s - %s", pluginId, errorMessage));
    sendCompletion(false, null, errorMessage, null);
  }

  private void sendCompletion(boolean success, String outputPath, String msg, String encryptionId) {
    if (!enabled) {
      return;
    }

    try {
      String completionMessage;
      if (encryptionId != null) {
        completionMessage = String.format(
            "{\"type\":\"COMPLETION\",\"success\":%b,\"outputPath\":\"%s\",\"message\":\"%s\",\"encryptionId\":\"%s\",\"timestamp\":%d,\"sessionId\":\"%s\"}",
            success,
            outputPath != null ? escapeJson(outputPath) : "",
            escapeJson(msg),
            escapeJson(encryptionId),
            System.currentTimeMillis(),
            sessionId);
      } else {
        completionMessage = String.format(
            "{\"type\":\"COMPLETION\",\"success\":%b,\"outputPath\":\"%s\",\"message\":\"%s\",\"timestamp\":%d,\"sessionId\":\"%s\"}",
            success,
            outputPath != null ? escapeJson(outputPath) : "",
            escapeJson(msg),
            System.currentTimeMillis(),
            sessionId);
      }

      String routingKey = ROUTING_KEY_PREFIX + sessionId + ".completion";
      channel.basicPublish(EXCHANGE_NAME, routingKey, null, completionMessage.getBytes(StandardCharsets.UTF_8));

      log.info("Sent completion notification to RabbitMQ");
    } catch (Exception e) {
      log.warn("Failed to send completion notification: {}", e.getMessage());
    }
  }

  private String escapeJson(String text) {
    if (text == null) {
      return "";
    }
    return text.replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t");
  }

  @Override
  public void close() {
    try {
      if (channel != null && channel.isOpen()) {
        channel.close();
      }
      if (connection != null && connection.isOpen()) {
        connection.close();
      }
      log.info("RabbitMQ connection closed for session: {}", sessionId);
    } catch (IOException | TimeoutException e) {
      log.warn("Error closing RabbitMQ connection: {}", e.getMessage());
    }
  }

  public void sendProgress(int percent, String message) {
    if (!enabled) {
      return;
    }

    int safePercent = Math.max(0, Math.min(100, percent));

    try {
      String progressMessage = String.format(
          "{\"type\":\"PROGRESS\",\"percent\":%d,\"message\":\"%s\",\"timestamp\":%d,\"sessionId\":\"%s\"}",
          safePercent,
          escapeJson(message),
          System.currentTimeMillis(),
          sessionId);

      String routingKey = ROUTING_KEY_PREFIX + sessionId + ".progress";
      channel.basicPublish(EXCHANGE_NAME, routingKey, null, progressMessage.getBytes(StandardCharsets.UTF_8));
    } catch (Exception e) {
      log.debug("Failed to send progress to RabbitMQ: {}", e.getMessage());
    }
  }
}
