package dev.neuralabs.auth.messaging;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

@Slf4j
public class RabbitMQLogListener implements AutoCloseable {

  private static final String EXCHANGE_NAME = "nebeniac.protector.logs";

  private Connection connection;
  private Channel channel;
  private final Gson gson = new Gson();

  private final Map<String, Consumer<String>> sessionCallbacks = new ConcurrentHashMap<>();
  private final Map<String, Consumer<CompletionMessage>> completionCallbacks = new ConcurrentHashMap<>();
  private final Map<String, BiConsumer<Integer, String>> progressCallbacks = new ConcurrentHashMap<>();

  public RabbitMQLogListener() {
    initializeConnection();
  }

  private void initializeConnection() {
    String rabbitHost = System.getenv().getOrDefault("RABBITMQ_HOST", "localhost");
    int rabbitPort = Integer.parseInt(System.getenv().getOrDefault("RABBITMQ_PORT", "5672"));
    String rabbitUsername = System.getenv().getOrDefault("RABBITMQ_USERNAME", "nebeniac");
    String rabbitPassword = System.getenv().getOrDefault("RABBITMQ_PASSWORD", "tuputamadre02");

    int maxRetries = 30;
    int retryDelay = 2000;

    for (int attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        log.info("Connecting to RabbitMQ at {}:{} (attempt {}/{})...", rabbitHost, rabbitPort, attempt, maxRetries);

        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost(rabbitHost);
        factory.setPort(rabbitPort);
        factory.setUsername(rabbitUsername);
        factory.setPassword(rabbitPassword);
        factory.setAutomaticRecoveryEnabled(true);
        factory.setNetworkRecoveryInterval(5000);
        factory.setConnectionTimeout(5000);

        this.connection = factory.newConnection();
        this.channel = connection.createChannel();

        channel.exchangeDeclare(EXCHANGE_NAME, "topic", true);

        log.info("RabbitMQ connection established successfully");
        return;

      } catch (Exception e) {
        if (attempt == maxRetries) {
          log.error("Failed to initialize RabbitMQ connection after {} attempts", maxRetries, e);
          throw new RuntimeException("Failed to initialize RabbitMQ Log Listener after " + maxRetries + " attempts", e);
        }

        log.warn("Failed to connect to RabbitMQ (attempt {}/{}): {}. Retrying in {}ms...",
            attempt, maxRetries, e.getMessage(), retryDelay);

        try {
          Thread.sleep(retryDelay);
        } catch (InterruptedException ie) {
          Thread.currentThread().interrupt();
          throw new RuntimeException("Interrupted while waiting to retry RabbitMQ connection", ie);
        }
      }
    }
  }

  public void listenForSession(String sessionId,
                               Consumer<String> logCallback,
                               BiConsumer<Integer, String> progressCallback,
                               Consumer<CompletionMessage> completionCallback) {
    try {
      sessionCallbacks.put(sessionId, logCallback);
      if (completionCallback != null) {
        completionCallbacks.put(sessionId, completionCallback);
      }
      if (progressCallback != null) {
        progressCallbacks.put(sessionId, progressCallback);
      }

      String queueName = "protector.logs." + sessionId;
      channel.queueDeclare(queueName, false, false, true, null);

      String routingKeyLogs = "protector.session." + sessionId;
      channel.queueBind(queueName, EXCHANGE_NAME, routingKeyLogs);

      String routingKeyCompletion = "protector.session." + sessionId + ".completion";
      channel.queueBind(queueName, EXCHANGE_NAME, routingKeyCompletion);

      String routingKeyProgress = "protector.session." + sessionId + ".progress";
      channel.queueBind(queueName, EXCHANGE_NAME, routingKeyProgress);

      DeliverCallback deliverCallback = (consumerTag, delivery) -> {
        String message = new String(delivery.getBody(), StandardCharsets.UTF_8);
        handleMessage(sessionId, message, delivery.getEnvelope().getRoutingKey());
      };

      channel.basicConsume(queueName, true, deliverCallback, consumerTag -> {
        log.info("Consumer cancelled for session: {}", sessionId);
      });

      log.info("Started listening for session: {}", sessionId);

    } catch (IOException e) {
      log.error("Failed to start listening for session: {}", sessionId, e);
    }
  }

  private void handleMessage(String sessionId, String message, String routingKey) {
    try {
      JsonObject json = gson.fromJson(message, JsonObject.class);

      String type = json.has("type") ? json.get("type").getAsString() : "LOG";

      switch (type) {
        case "COMPLETION":
          handleCompletionMessage(sessionId, json);
          break;
        case "PROGRESS":
          handleProgressMessage(sessionId, json);
          break;
        default:
          handleLogMessage(sessionId, json);
          break;
      }

    } catch (Exception e) {
      log.error("Error handling message for session {}: {}", sessionId, message, e);
    }
  }

  private void handleLogMessage(String sessionId, JsonObject json) {
    String level = json.has("level") ? json.get("level").getAsString() : "INFO";
    String logMessage = json.has("message") ? json.get("message").getAsString() : "";

    Consumer<String> callback = sessionCallbacks.get(sessionId);
    if (callback != null) {
      String formattedLog = String.format("[%s] %s", level, logMessage);
      callback.accept(formattedLog);
    }
  }

  private void handleCompletionMessage(String sessionId, JsonObject json) {
    boolean success = json.has("success") && json.get("success").getAsBoolean();
    String outputPath = json.has("outputPath") ? json.get("outputPath").getAsString() : null;
    String message = json.has("message") ? json.get("message").getAsString() : "";
    String encryptionId = json.has("encryptionId") ? json.get("encryptionId").getAsString() : null;
    String encryptionKey = json.has("encryptionKey") ? json.get("encryptionKey").getAsString() : null;
    String signature = json.has("signature") ? json.get("signature").getAsString() : null;

    CompletionMessage completion = new CompletionMessage(success, outputPath, message, encryptionId, encryptionKey, signature);

    Consumer<CompletionMessage> callback = completionCallbacks.get(sessionId);
    if (callback != null) {
      callback.accept(completion);
    }

    sessionCallbacks.remove(sessionId);
    completionCallbacks.remove(sessionId);
    progressCallbacks.remove(sessionId);

    log.info("Session {} completed: success={}, message={}", sessionId, success, message);
  }

  private void handleProgressMessage(String sessionId, JsonObject json) {
    int percent = json.has("percent") ? json.get("percent").getAsInt() : 0;
    String progressMessage = json.has("message") ? json.get("message").getAsString() : "";

    BiConsumer<Integer, String> callback = progressCallbacks.get(sessionId);
    if (callback != null) {
      callback.accept(percent, progressMessage);
    }
  }

  public void stopListeningForSession(String sessionId) {
    sessionCallbacks.remove(sessionId);
    completionCallbacks.remove(sessionId);
    progressCallbacks.remove(sessionId);
    log.info("Stopped listening for session: {}", sessionId);
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
      log.info("RabbitMQ Log Listener closed");
    } catch (IOException | TimeoutException e) {
      log.warn("Error closing RabbitMQ connection: {}", e.getMessage());
    }
  }

  public static class CompletionMessage {
    private final boolean success;
    private final String outputPath;
    private final String message;
    private final String encryptionId;
    private final String encryptionKey;
    private final String signature;

    public CompletionMessage(boolean success, String outputPath, String message, String encryptionId, String encryptionKey, String signature) {
      this.success = success;
      this.outputPath = outputPath;
      this.message = message;
      this.encryptionId = encryptionId;
      this.encryptionKey = encryptionKey;
      this.signature = signature;
    }

    public boolean isSuccess() {
      return success;
    }

    public String getOutputPath() {
      return outputPath;
    }

    public String getMessage() {
      return message;
    }

    public String getEncryptionId() {
      return encryptionId;
    }

    public String getEncryptionKey() {
      return encryptionKey;
    }

    public String getSignature() {
      return signature;
    }
  }
}
