package dev.neuralabs.auth.websocket;

import com.google.common.collect.Maps;
import com.google.gson.Gson;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.java_websocket.WebSocket;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class EncryptionWebSocketHandler extends WebSocketServer {
  private final Map<String, WebSocket> sessions = new ConcurrentHashMap<>();
  private final Gson gson = new Gson();

  public EncryptionWebSocketHandler(int port) {
    super(new InetSocketAddress(port));
    log.info("WebSocket server initialized on port: {}", port);
  }

  @Override
  public void onOpen(WebSocket conn, ClientHandshake handshake) {
    String sessionId = extractSessionId(handshake);
    if (sessionId != null) {
      sessions.put(sessionId, conn);
      log.info("WebSocket connection opened for session: {}", sessionId);

      sendMessage(conn, new WebSocketMessage("connection", "Connected to encryption service", "info"));
    } else {
      log.warn("WebSocket connection rejected - no session ID provided");
      conn.close();
    }
  }

  @Override
  public void onClose(WebSocket conn, int code, String reason, boolean remote) {
    String sessionId = findSessionId(conn);
    if (sessionId != null) {
      sessions.remove(sessionId);
      log.info("WebSocket connection closed for session: {}", sessionId);
    }
  }

  @Override
  public void onMessage(WebSocket conn, String message) {
    log.debug("Received WebSocket message: {}", message);
  }

  @Override
  public void onError(WebSocket conn, Exception ex) {
    log.error("WebSocket error", ex);
    String sessionId = findSessionId(conn);
    if (sessionId != null) {
      sessions.remove(sessionId);
    }
  }

  @Override
  public void onStart() {
    log.info("WebSocket server started successfully");
  }

  public void sendLogToSession(String sessionId, String logMessage, String level) {
    WebSocket conn = sessions.get(sessionId);
    if (conn != null && conn.isOpen()) {
      sendMessage(conn, new WebSocketMessage("log", logMessage, level));
    }
  }

  public void sendProgressToSession(String sessionId, int progress) {
    WebSocket conn = sessions.get(sessionId);
    if (conn != null && conn.isOpen()) {
      sendMessage(conn, new WebSocketMessage("progress", String.valueOf(progress), "info"));
    }
  }

  public void sendCompletionToSession(String sessionId, boolean success, String downloadUrl) {
    sendCompletionToSession(sessionId, success, downloadUrl, null, null, null);
  }

  public void sendCompletionToSession(String sessionId, boolean success, String downloadUrl, String encryptionId,
                                      String pluginId, String pluginVersion) {
    WebSocket conn = sessions.get(sessionId);
    if (conn != null && conn.isOpen()) {
      Map<String, Object> data = Maps.newHashMap();
      data.put("success", success);
      data.put("downloadUrl", downloadUrl != null ? downloadUrl : "");
      if (encryptionId != null)
        data.put("encryptionId", encryptionId);
      if (pluginId != null)
        data.put("pluginId", pluginId);
      if (pluginVersion != null)
        data.put("pluginVersion", pluginVersion);
      sendMessage(conn, new WebSocketMessage("completion", gson.toJson(data), success ? "success" : "error"));
    }
  }

  public void sendDockerErrorToSession(String sessionId, String errorMessage) {
    WebSocket conn = sessions.get(sessionId);
    if (conn != null && conn.isOpen()) {
      sendMessage(conn, new WebSocketMessage("log", "Docker Error: " + errorMessage, "error"));
      sendMessage(conn, new WebSocketMessage("log", "Please check Docker configuration and try again", "error"));

      Map<String, Object> data = Map.of(
          "success", false,
          "error", "Docker configuration error",
          "details", errorMessage);
      sendMessage(conn, new WebSocketMessage("completion", gson.toJson(data), "error"));
    }
  }

  private void sendMessage(WebSocket conn, WebSocketMessage message) {
    try {
      String jsonMessage = gson.toJson(message);
      conn.send(jsonMessage);
    } catch (Exception e) {
      log.error("Failed to send WebSocket message", e);
    }
  }

  private String extractSessionId(ClientHandshake handshake) {
    String uri = handshake.getResourceDescriptor();
    if (uri.contains("sessionId=")) {
      return uri.substring(uri.indexOf("sessionId=") + 10);
    }
    return null;
  }

  private String findSessionId(WebSocket conn) {
    for (Map.Entry<String, WebSocket> entry : sessions.entrySet()) {
      if (entry.getValue() == conn) {
        return entry.getKey();
      }
    }
    return null;
  }

  @Getter
  public static class WebSocketMessage {
    private final String type;
    private final String message;
    private final String level;
    private final long timestamp;

    public WebSocketMessage(String type, String message, String level) {
      this.type = type;
      this.message = message;
      this.level = level;
      this.timestamp = System.currentTimeMillis();
    }
  }
}
