package dev.neuralabs.auth.config;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

@Data
@Slf4j
public class AuthConfig {

  public enum EmailProvider {
    GMAIL_API, SMTP
  }

  public enum DatabaseType {
    LOCAL, MONGODB
  }

  private static AuthConfig instance;

  private DatabaseType databaseType = DatabaseType.LOCAL;
  private String mongoConnectionString = "";
  private String mongoDatabaseName = "nebeniac";
  private String mongoUsername = "";
  private String mongoPassword = "";

  private int serverPort = 8080;
  private String baseUrl = "http://localhost:3000";

  private String jwtSecret = "your-super-secret-jwt-key-change-this-in-production";
  private int jwtExpirationHours = 24;
  private String jwtIssuer = "nebeniac-auth";

  private int sessionTimeoutHours = 24;
  private int sessionCleanupIntervalMinutes = 60;

  private boolean emailEnabled = true;
  private String emailFrom = "noreply@nebeniac.com";
  private EmailProvider emailProvider = EmailProvider.GMAIL_API;

  private String googleOAuthClientId = "";
  private String googleOAuthClientSecret = "";
  private String googleOAuthRefreshToken = "";

  private String smtpHost = "smtp.gmail.com";
  private int smtpPort = 587;
  private String smtpUsername = "";
  private String smtpPassword = "";
  private boolean smtpTlsEnabled = true;

  private int passwordMinLength = 8;
  private boolean passwordRequireUppercase = true;
  private boolean passwordRequireLowercase = true;
  private boolean passwordRequireNumbers = true;
  private boolean passwordRequireSpecialChars = false;

  private boolean accountLockoutEnabled = true;
  private int accountLockoutMaxAttempts = 5;
  private int accountLockoutDurationMinutes = 30;

  private int emailVerificationTokenExpirationHours = 24;
  private int passwordResetTokenExpirationHours = 1;

  private boolean pluginDownloadEnabled = true;
  private boolean pluginLicenseAutoGenerate = true;
  private int pluginLicenseDefaultExpirationDays = 30;
  private boolean pluginProtectionEnabled = true;
  private String pluginEncryptionAlgorithm = "AES-256-GCM";

  private boolean auditEnabled = true;
  private int auditRetentionDays = 90;
  private boolean requestLoggingEnabled = true;
  private boolean requestLoggingIncludeBody = false;

  private boolean devMode = true;

  private boolean corsEnabled = true;
  private String corsAllowedOrigins = "*";
  private String corsAllowedMethods = "GET,POST,PUT,DELETE,OPTIONS";
  private String corsAllowedHeaders = "Content-Type,Authorization";

  private AuthConfig() {
    loadConfiguration();
  }

  public static synchronized AuthConfig getInstance() {
    if (instance == null) {
      instance = new AuthConfig();
    }
    return instance;
  }

  private void loadConfiguration() {
    Properties props = new Properties();

    try (InputStream input = getClass().getClassLoader().getResourceAsStream("config.properties")) {
      if (input != null) {
        props.load(input);
        log.info("Loaded configuration from config.properties");
      } else {
        log.warn("config.properties not found in classpath, using defaults");
      }
    } catch (IOException e) {
      log.warn("Could not load config.properties, using defaults", e);
    }

    loadDatabaseConfig(props);
    loadServerConfig(props);
    loadJwtConfig(props);
    loadSessionConfig(props);
    loadEmailConfig(props);
    loadSecurityConfig(props);
    loadPluginConfig(props);
    loadAuditConfig(props);
    loadDevelopmentConfig(props);
    loadCorsConfig(props);

    log.info("Authentication configuration loaded successfully");

    validateConfiguration();
  }

  private void loadDatabaseConfig(Properties props) {
    String databaseTypeStr = getProperty(props, "database.type", "DATABASE_TYPE", "LOCAL");

    try {
      this.databaseType = DatabaseType.valueOf(databaseTypeStr.toUpperCase());
    } catch (IllegalArgumentException e) {
      log.warn("Invalid database type '{}', using LOCAL", databaseTypeStr);
      this.databaseType = DatabaseType.LOCAL;
    }

    this.mongoConnectionString = getProperty(props, "mongodb.connection.string", "MONGODB_CONNECTION_STRING", "");
    this.mongoDatabaseName = getProperty(props, "mongodb.database.name", "MONGODB_DATABASE_NAME", "nebeniac");
    this.mongoUsername = getProperty(props, "mongodb.username", "MONGODB_USERNAME", "");
    this.mongoPassword = getProperty(props, "mongodb.password", "MONGODB_PASSWORD", "");

    log.info("Database configuration loaded - Type: {}", this.databaseType);
    if (this.databaseType == DatabaseType.MONGODB) {
      log.info("MongoDB Database: {}", this.mongoDatabaseName);
      if (this.mongoConnectionString.isEmpty()) {
        log.warn("MongoDB connection string is empty! Database operations will fail.");
      }
    }
  }

  private void loadServerConfig(Properties props) {
    this.serverPort = getIntProperty(props, "server.port", "SERVER_PORT", 8080);
    this.baseUrl = getProperty(props, "app.base.url", "APP_BASE_URL", "http://localhost:3000");
  }

  private void loadJwtConfig(Properties props) {
    this.jwtSecret = getProperty(props, "jwt.secret", "JWT_SECRET",
        "your-super-secret-jwt-key-change-this-in-production");
    this.jwtExpirationHours = getIntProperty(props, "jwt.expiration.hours", "JWT_EXPIRATION_HOURS", 24);
    this.jwtIssuer = getProperty(props, "jwt.issuer", "JWT_ISSUER", "nebeniac-auth");

    if ("your-super-secret-jwt-key-change-this-in-production".equals(this.jwtSecret)) {
      log.warn("Using default JWT secret! Please change jwt.secret in config.properties for production use");
    }
  }

  private void loadSessionConfig(Properties props) {
    this.sessionTimeoutHours = getIntProperty(props, "session.timeout.hours", "SESSION_TIMEOUT_HOURS", 24);
    this.sessionCleanupIntervalMinutes = getIntProperty(props, "session.cleanup.interval.minutes",
        "SESSION_CLEANUP_INTERVAL_MINUTES", 60);
  }

  private void loadEmailConfig(Properties props) {
    this.emailEnabled = getBooleanProperty(props, "email.enabled", "EMAIL_ENABLED", true);
    this.emailFrom = getProperty(props, "email.from", "EMAIL_FROM", "noreply@nebeniac.com");

    String providerStr = getProperty(props, "email.provider", "EMAIL_PROVIDER", "GMAIL_API");
    try {
      this.emailProvider = EmailProvider.valueOf(providerStr.toUpperCase());
    } catch (IllegalArgumentException e) {
      log.warn("Invalid email provider '{}', using GMAIL_API", providerStr);
      this.emailProvider = EmailProvider.GMAIL_API;
    }

    this.googleOAuthClientId = getProperty(props, "google.oauth.client.id", "GOOGLE_OAUTH_CLIENT_ID", "");
    this.googleOAuthClientSecret = getProperty(props, "google.oauth.client.secret", "GOOGLE_OAUTH_CLIENT_SECRET",
        "");
    this.googleOAuthRefreshToken = getProperty(props, "google.oauth.refresh.token", "GOOGLE_OAUTH_REFRESH_TOKEN",
        "");

    this.smtpHost = getProperty(props, "smtp.host", "SMTP_HOST", "smtp.gmail.com");
    this.smtpPort = getIntProperty(props, "smtp.port", "SMTP_PORT", 587);
    this.smtpUsername = getProperty(props, "smtp.username", "SMTP_USERNAME", "");
    this.smtpPassword = getProperty(props, "smtp.password", "SMTP_PASSWORD", "");
    this.smtpTlsEnabled = getBooleanProperty(props, "smtp.tls.enabled", "SMTP_TLS_ENABLED", true);
  }

  private void loadSecurityConfig(Properties props) {
    this.passwordMinLength = getIntProperty(props, "password.min.length", "PASSWORD_MIN_LENGTH", 8);
    this.passwordRequireUppercase = getBooleanProperty(props, "password.require.uppercase",
        "PASSWORD_REQUIRE_UPPERCASE", true);
    this.passwordRequireLowercase = getBooleanProperty(props, "password.require.lowercase",
        "PASSWORD_REQUIRE_LOWERCASE", true);
    this.passwordRequireNumbers = getBooleanProperty(props, "password.require.numbers", "PASSWORD_REQUIRE_NUMBERS",
        true);
    this.passwordRequireSpecialChars = getBooleanProperty(props, "password.require.special.chars",
        "PASSWORD_REQUIRE_SPECIAL_CHARS", false);

    this.accountLockoutEnabled = getBooleanProperty(props, "account.lockout.enabled", "ACCOUNT_LOCKOUT_ENABLED",
        true);
    this.accountLockoutMaxAttempts = getIntProperty(props, "account.lockout.max.attempts",
        "ACCOUNT_LOCKOUT_MAX_ATTEMPTS", 5);
    this.accountLockoutDurationMinutes = getIntProperty(props, "account.lockout.duration.minutes",
        "ACCOUNT_LOCKOUT_DURATION_MINUTES", 30);

    this.emailVerificationTokenExpirationHours = getIntProperty(props, "email.verification.token.expiration.hours",
        "EMAIL_VERIFICATION_TOKEN_EXPIRATION_HOURS", 24);
    this.passwordResetTokenExpirationHours = getIntProperty(props, "password.reset.token.expiration.hours",
        "PASSWORD_RESET_TOKEN_EXPIRATION_HOURS", 1);
  }

  private void loadPluginConfig(Properties props) {
    this.pluginDownloadEnabled = getBooleanProperty(props, "plugin.download.enabled", "PLUGIN_DOWNLOAD_ENABLED",
        true);
    this.pluginLicenseAutoGenerate = getBooleanProperty(props, "plugin.license.auto.generate",
        "PLUGIN_LICENSE_AUTO_GENERATE", true);
    this.pluginLicenseDefaultExpirationDays = getIntProperty(props, "plugin.license.default.expiration.days",
        "PLUGIN_LICENSE_DEFAULT_EXPIRATION_DAYS", 30);
    this.pluginProtectionEnabled = getBooleanProperty(props, "plugin.protection.enabled",
        "PLUGIN_PROTECTION_ENABLED", true);
    this.pluginEncryptionAlgorithm = getProperty(props, "plugin.encryption.algorithm",
        "PLUGIN_ENCRYPTION_ALGORITHM", "AES-256-GCM");
  }

  private void loadAuditConfig(Properties props) {
    this.auditEnabled = getBooleanProperty(props, "audit.enabled", "AUDIT_ENABLED", true);
    this.auditRetentionDays = getIntProperty(props, "audit.retention.days", "AUDIT_RETENTION_DAYS", 90);
    this.requestLoggingEnabled = getBooleanProperty(props, "request.logging.enabled", "REQUEST_LOGGING_ENABLED",
        true);
    this.requestLoggingIncludeBody = getBooleanProperty(props, "request.logging.include.body",
        "REQUEST_LOGGING_INCLUDE_BODY", false);
  }

  private void loadDevelopmentConfig(Properties props) {
    this.devMode = getBooleanProperty(props, "dev.mode", "DEV_MODE", true);
  }

  private void loadCorsConfig(Properties props) {
    this.corsEnabled = getBooleanProperty(props, "cors.enabled", "CORS_ENABLED", true);
    this.corsAllowedOrigins = getProperty(props, "cors.allowed.origins", "CORS_ALLOWED_ORIGINS", "*");
    this.corsAllowedMethods = getProperty(props, "cors.allowed.methods", "CORS_ALLOWED_METHODS",
        "GET,POST,PUT,DELETE,OPTIONS");
    this.corsAllowedHeaders = getProperty(props, "cors.allowed.headers", "CORS_ALLOWED_HEADERS",
        "Content-Type,Authorization");
  }

  private void validateConfiguration() {
    if (databaseType == DatabaseType.MONGODB && !isMongoConfigured()) {
      log.error(
          "MongoDB is selected but connection string is not configured! Please set mongodb.connection.string in config.properties");
    }

    if (emailEnabled && emailProvider == EmailProvider.GMAIL_API) {
      if (googleOAuthClientId.isEmpty() || googleOAuthClientSecret.isEmpty()
          || googleOAuthRefreshToken.isEmpty()) {
        log.warn(
            "Gmail API email provider is enabled but Google OAuth credentials are not configured. Email functionality will not work.");
      }
    }

    if (emailEnabled && emailProvider == EmailProvider.SMTP) {
      if (smtpUsername.isEmpty() || smtpPassword.isEmpty()) {
        log.warn(
            "SMTP email provider is enabled but SMTP credentials are not configured. Email functionality will not work.");
      }
    }

    if (jwtSecret.length() < 32) {
      log.warn("JWT secret is too short. Consider using a longer secret for better security.");
    }
  }

  private String getProperty(Properties props, String propKey, String envKey, String defaultValue) {
    String value = props.getProperty(propKey);
    if (value != null && !value.trim().isEmpty()) {
      return value.trim();
    }

    value = System.getenv(envKey);
    if (value != null && !value.trim().isEmpty()) {
      return value.trim();
    }

    return defaultValue;
  }

  private int getIntProperty(Properties props, String propKey, String envKey, int defaultValue) {
    String value = getProperty(props, propKey, envKey, String.valueOf(defaultValue));
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      log.warn("Invalid integer value '{}' for property '{}', using default: {}", value, propKey, defaultValue);
      return defaultValue;
    }
  }

  private boolean getBooleanProperty(Properties props, String propKey, String envKey, boolean defaultValue) {
    String value = getProperty(props, propKey, envKey, String.valueOf(defaultValue));
    return Boolean.parseBoolean(value);
  }

  public long getJwtExpirationMillis() {
    return jwtExpirationHours * 3600L * 1000L;
  }

  public long getSessionTimeoutMillis() {
    return sessionTimeoutHours * 3600L * 1000L;
  }

  public long getEmailVerificationTokenExpirationMillis() {
    return emailVerificationTokenExpirationHours * 3600L * 1000L;
  }

  public long getPasswordResetTokenExpirationMillis() {
    return passwordResetTokenExpirationHours * 3600L * 1000L;
  }

  public long getPluginLicenseDefaultExpirationMillis() {
    return pluginLicenseDefaultExpirationDays * 24L * 3600L * 1000L;
  }

  public boolean isGoogleOAuthConfigured() {
    return !googleOAuthClientId.isEmpty() &&
        !googleOAuthClientSecret.isEmpty() &&
        !googleOAuthRefreshToken.isEmpty();
  }

  public boolean isSmtpConfigured() {
    return !smtpUsername.isEmpty() && !smtpPassword.isEmpty();
  }

  public boolean isEmailConfigured() {
    if (!emailEnabled)
      return false;

    return (emailProvider == EmailProvider.GMAIL_API && isGoogleOAuthConfigured()) ||
        (emailProvider == EmailProvider.SMTP && isSmtpConfigured());
  }

  public boolean isMongoConfigured() {
    return !mongoConnectionString.isEmpty() && !mongoDatabaseName.isEmpty();
  }

  public boolean isDatabaseConfigured() {
    if (databaseType == DatabaseType.LOCAL) {
      return true;
    } else if (databaseType == DatabaseType.MONGODB) {
      return isMongoConfigured();
    }
    return false;
  }
}
