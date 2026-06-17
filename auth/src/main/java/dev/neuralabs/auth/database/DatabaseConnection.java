package dev.neuralabs.auth.database;

import dev.neuralabs.auth.config.DatabaseConfig;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class DatabaseConnection {

  private static DatabaseConnection instance;
  private DatabaseInterface database;
  private boolean initialized = false;
  private final DatabaseConfig config;

  private DatabaseConnection() {
    this.config = DatabaseConfig.getInstance();
  }

  public static synchronized DatabaseConnection getInstance() {
    if (instance == null) {
      instance = new DatabaseConnection();
    }
    return instance;
  }

  public void initialize() {
    if (!initialized) {
      log.info("Initializing database connection - Type: {}", config.getDatabaseType());

      try {
        if (config.isMongoEnabled()) {
          log.info("Using MongoDB database");
          database = MongoConnection.getInstance();
        } else {
          log.info("Using local file database");
          database = LocalDatabase.getInstance();
        }

        database.initialize();
        initialized = true;
        log.info("Database connection initialized successfully");

      } catch (Exception e) {
        log.error("Failed to initialize database", e);


        if (config.isMongoEnabled()) {
          log.warn("MongoDB initialization failed, falling back to local database");
          try {
            database = LocalDatabase.getInstance();
            database.initialize();
            initialized = true;
            log.info("Fallback to local database successful");
          } catch (Exception fallbackError) {
            log.error("Fallback to local database also failed", fallbackError);
            throw new RuntimeException("Could not initialize any database", fallbackError);
          }
        } else {
          throw new RuntimeException("Could not initialize local database", e);
        }
      }
    }
  }

  public DatabaseInterface getDatabase() {
    if (!initialized) {
      throw new IllegalStateException("Database not initialized");
    }
    return database;
  }

  public boolean isConnected() {
    return initialized && database != null;
  }

  public boolean isHealthy() {
    return isConnected() && database.isHealthy();
  }

  public String getDatabaseType() {
    return config.getDatabaseType().toString();
  }

  public void close() {
    if (initialized && database != null) {
      log.info("Closing database connection...");
      database.shutdown();
      initialized = false;
      log.info("Database connection closed");
    }
  }
}
