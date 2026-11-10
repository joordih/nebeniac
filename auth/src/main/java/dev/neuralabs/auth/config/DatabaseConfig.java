package dev.neuralabs.auth.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Data
@Slf4j
public class DatabaseConfig {
  public enum DatabaseType {
    LOCAL, MONGODB
  }

  private static DatabaseConfig instance;
  private AuthConfig authConfig;

  private DatabaseConfig() {
    this.authConfig = AuthConfig.getInstance();
    log.info("DatabaseConfig initialized with type: {}", getDatabaseType());
  }

  public static synchronized DatabaseConfig getInstance() {
    if (instance == null) {
      instance = new DatabaseConfig();
    }
    return instance;
  }

  public DatabaseType getDatabaseType() {
    return authConfig.getDatabaseType() == AuthConfig.DatabaseType.MONGODB ?
        DatabaseType.MONGODB : DatabaseType.LOCAL;
  }

  public String getMongoConnectionString() {
    return authConfig.getMongoConnectionString();
  }

  public String getMongoDatabaseName() {
    return authConfig.getMongoDatabaseName();
  }

  public String getMongoUsername() {
    return authConfig.getMongoUsername();
  }

  public String getMongoPassword() {
    return authConfig.getMongoPassword();
  }

  public boolean isMongoConfigured() {
    return authConfig.isMongoConfigured();
  }

  public boolean isMongoEnabled() {
    return getDatabaseType() == DatabaseType.MONGODB;
  }
}
