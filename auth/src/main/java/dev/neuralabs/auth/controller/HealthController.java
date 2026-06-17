package dev.neuralabs.auth.controller;

import com.google.gson.Gson;
import dev.neuralabs.auth.database.DatabaseConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Request;
import spark.Response;

import java.util.HashMap;
import java.util.Map;


public class HealthController {

  private static final Logger logger = LoggerFactory.getLogger(HealthController.class);
  private final Gson gson;

  public HealthController() {
    this.gson = new Gson();
  }

  public String healthCheck(Request request, Response response) {
    response.type("application/json");

    try {
      Map<String, Object> health = new HashMap<>();


      boolean dbHealthy = DatabaseConnection.getInstance().isHealthy();

      health.put("status", dbHealthy ? "healthy" : "unhealthy");
      health.put("timestamp", System.currentTimeMillis());
      health.put("database", dbHealthy ? "connected" : "disconnected");
      health.put("version", "1.0.0-LOCAL");
      health.put("uptime", getUptime());

      if (dbHealthy) {

        Map<String, Object> stats = DatabaseConnection.getInstance().getDatabase().getStatistics();
        health.put("statistics", stats);
        response.status(200);
      } else {
        response.status(503);
      }

      return gson.toJson(health);

    } catch (Exception e) {
      logger.error("Error in health check", e);
      response.status(500);

      Map<String, Object> error = new HashMap<>();
      error.put("status", "error");
      error.put("message", "Internal server error");
      error.put("timestamp", System.currentTimeMillis());

      return gson.toJson(error);
    }
  }

  public String getMetrics(Request request, Response response) {
    response.type("application/json");

    try {
      Map<String, Object> metrics = new HashMap<>();


      Runtime runtime = Runtime.getRuntime();
      metrics.put("memory", Map.of(
          "total", runtime.totalMemory(),
          "free", runtime.freeMemory(),
          "used", runtime.totalMemory() - runtime.freeMemory(),
          "max", runtime.maxMemory()
      ));

      metrics.put("threads", Thread.activeCount());
      metrics.put("uptime", getUptime());
      metrics.put("timestamp", System.currentTimeMillis());


      if (DatabaseConnection.getInstance().isHealthy()) {
        Map<String, Object> dbStats = DatabaseConnection.getInstance().getDatabase().getStatistics();
        metrics.put("database", dbStats);
      }

      return gson.toJson(metrics);

    } catch (Exception e) {
      logger.error("Error fetching metrics", e);
      response.status(500);

      Map<String, Object> error = new HashMap<>();
      error.put("error", "Error fetching metrics");
      error.put("timestamp", System.currentTimeMillis());

      return gson.toJson(error);
    }
  }

  private long getUptime() {
    return System.currentTimeMillis() - startTime;
  }

  private static final long startTime = System.currentTimeMillis();
}
