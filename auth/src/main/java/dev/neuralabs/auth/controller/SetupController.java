package dev.neuralabs.auth.controller;

import static dev.neuralabs.auth.controller.ControllerSupport.error;

import com.google.gson.Gson;
import dev.neuralabs.auth.config.AuthConfig;
import dev.neuralabs.auth.database.DatabaseConnection;
import dev.neuralabs.auth.database.DatabaseInterface;
import dev.neuralabs.auth.model.AuditLog;
import dev.neuralabs.auth.model.User;
import dev.neuralabs.auth.security.SecretStore;
import dev.neuralabs.auth.service.EmailService;
import dev.neuralabs.auth.util.GsonUtil;
import dev.neuralabs.auth.util.PasswordUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.bson.types.ObjectId;
import spark.Request;
import spark.Response;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Slf4j
public class SetupController {
  private final DatabaseInterface database;
  private final Gson gson;
  private final AuthConfig config;
  private final EmailService emailService;
  private final Object setupLock = new Object();
  private final String setupToken;

  public SetupController() {
    this.database = DatabaseConnection.getInstance().getDatabase();
    this.config = AuthConfig.getInstance();
    this.gson = GsonUtil.build();
    this.emailService = new EmailService(config);
    this.setupToken = database.findAllUsers().isEmpty()
        ? SecretStore.loadOrCreate("NEBENIAC_SETUP_TOKEN", SETUP_TOKEN_FILE, 24)
        : null;
    if (setupToken != null) {
      log.warn("Initial setup pending: an administrator can only be created with the setup token "
          + "(NEBENIAC_SETUP_TOKEN or the {} file in the secrets directory)", SETUP_TOKEN_FILE);
    }
  }

  private static final String SETUP_TOKEN_FILE = "setup_token";
  private static final String SETUP_TOKEN_HEADER = "X-Setup-Token";

  private boolean hasValidSetupToken(Request request) {
    String provided = request.headers(SETUP_TOKEN_HEADER);
    return setupToken != null && provided != null && MessageDigest.isEqual(
        setupToken.getBytes(StandardCharsets.UTF_8), provided.trim().getBytes(StandardCharsets.UTF_8));
  }

  private String rejectSetup(Request request, Response response) {
    if (!database.findAllUsers().isEmpty()) {
      return error(response, 403, "The system already has users configured. This endpoint is only for initial setup.");
    }
    if (!hasValidSetupToken(request)) {
      log.warn("Rejected initial setup attempt without a valid setup token from {}", request.ip());
      return error(response, 403, "Valid setup token required");
    }
    return null;
  }

  public String createFirstAdmin(Request request, Response response) {
    try {
      String rejection = rejectSetup(request, response);
      if (rejection != null) {
        return rejection;
      }

      CreateFirstAdminRequest adminRequest = gson.fromJson(request.body(), CreateFirstAdminRequest.class);

      if (adminRequest == null ||
          adminRequest.getEmail() == null || adminRequest.getEmail().trim().isEmpty() ||
          adminRequest.getPassword() == null || adminRequest.getPassword().trim().isEmpty() ||
          adminRequest.getFirstName() == null || adminRequest.getFirstName().trim().isEmpty() ||
          adminRequest.getLastName() == null || adminRequest.getLastName().trim().isEmpty()) {
        return error(response, 400, "Email, password, first name and last name are required");
      }

      if (!isValidEmail(adminRequest.getEmail())) {
        return error(response, 400, "Invalid email format");
      }

      String passwordError = PasswordUtil.validatePassword(adminRequest.getPassword(), config);
      if (passwordError != null) {
        return error(response, 400, passwordError);
      }

      User admin = User.builder()
          .id(new ObjectId().toHexString())
          .email(adminRequest.getEmail().trim().toLowerCase())
          .username(adminRequest.getUsername() != null ? adminRequest.getUsername().trim() : "admin")
          .firstName(adminRequest.getFirstName().trim())
          .lastName(adminRequest.getLastName().trim())
          .passwordHash(PasswordUtil.hashPassword(adminRequest.getPassword()))
          .role("ADMIN")
          .active(true)
          .emailVerified(true)
          .createdAt(Date.from(Instant.now()))
          .updatedAt(Date.from(Instant.now()))
          .permissions(List.of("ALL"))
          .build();

      synchronized (setupLock) {
        rejection = rejectSetup(request, response);
        if (rejection != null) {
          return rejection;
        }
        database.saveUser(admin);
      }
      SecretStore.delete(SETUP_TOKEN_FILE);

      logAuditEvent("ADMIN_CREATED", admin.getId(), request.ip(), true,
          "First administrator created:" + admin.getEmail());

      log.info("First administrator user created: {}", admin.getEmail());

      String emailStatus = "not_configured";
      if (config.isEmailConfigured()) {
        try {
          boolean emailSent = emailService.sendWelcomeAdminEmail(
              admin.getEmail(),
              admin.getFullName()
          );
          emailStatus = emailSent ? "sent" : "failed";
          if (!emailSent) {
            log.warn("Could not send welcome email to administrator: {}", admin.getEmail());
          }
        } catch (Exception e) {
          log.error("Error sending welcome email to administrator", e);
          emailStatus = "error";
        }
      }

      return gson.toJson(Map.of(
          "success", true,
          "message", "Admin user created successfully",
          "emailStatus", emailStatus,
          "admin", Map.of(
              "id", admin.getId(),
              "email", admin.getEmail(),
              "username", admin.getUsername(),
              "firstName", admin.getFirstName(),
              "lastName", admin.getLastName(),
              "role", admin.getRole(),
              "createdAt", admin.getCreatedAt()
          )
      ));
    } catch (Exception e) {
      log.error("Error creating first administrator", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String getSetupStatus(Request request, Response response) {
    try {
      boolean hasUsers = !database.findAllUsers().isEmpty();
      boolean isHealthy = database.isHealthy();

      return gson.toJson(Map.of(
          "success", true,
          "setupComplete", hasUsers,
          "hasUsers", hasUsers,
          "databaseHealthy", isHealthy,
          "needsInitialSetup", !hasUsers,
          "setupTokenRequired", !hasUsers,
          "message", hasUsers ?
              "System configured and ready to use" :
              "System needs initial setup — create the first administrator"
      ));
    } catch (Exception e) {
      log.error("Error checking system status", e);
      return error(response, 500, "Error checking system status");
    }
  }

  public String createDefaultAdmin(Request request, Response response) {
    try {
      if (!config.isDevMode()) {
        return error(response, 403, "This endpoint is only available in development mode");
      }

      String rejection = rejectSetup(request, response);
      if (rejection != null) {
        return rejection;
      }

      String password = PasswordUtil.generateToken();
      User admin = User.builder()
          .id(new ObjectId().toHexString())
          .email("admin@nebeniac.com")
          .username("admin")
          .firstName("Administrator")
          .lastName("System")
          .passwordHash(PasswordUtil.hashPassword(password))
          .role("ADMIN")
          .active(true)
          .emailVerified(true)
          .createdAt(Date.from(Instant.now()))
          .updatedAt(Date.from(Instant.now()))
          .permissions(List.of("ALL"))
          .build();

      synchronized (setupLock) {
        rejection = rejectSetup(request, response);
        if (rejection != null) {
          return rejection;
        }
        database.saveUser(admin);
      }
      SecretStore.delete(SETUP_TOKEN_FILE);

      log.warn("Default administrator user created for development: {}", admin.getEmail());

      return gson.toJson(Map.of(
          "success", true,
          "message", "Default administrator user created",
          "credentials", Map.of(
              "email", "admin@nebeniac.com",
              "password", password
          ),
          "warning", "This password is shown only once. Store it securely and change it after logging in."
      ));
    } catch (Exception e) {
      log.error("Error creating default administrator", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String getEmailStatus(Request request, Response response) {
    try {
      EmailService.EmailStatus status = emailService.getEmailStatus();

      return gson.toJson(Map.of(
          "success", true,
          "emailStatus", status
      ));
    } catch (Exception e) {
      log.error("Error fetching email status", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String sendTestEmail(Request request, Response response) {
    try {
      if (!config.isDevMode()) {
        return error(response, 403, "This endpoint is only available in development mode");
      }

      TestEmailRequest testRequest = gson.fromJson(request.body(), TestEmailRequest.class);

      if (testRequest == null || testRequest.getEmail() == null || testRequest.getEmail().trim().isEmpty()) {
        return error(response, 400, "Email is required");
      }

      if (!isValidEmail(testRequest.getEmail())) {
        return error(response, 400, "Invalid email format");
      }

      boolean emailSent = emailService.sendTestEmail(testRequest.getEmail());

      logAuditEvent("TEST_EMAIL_SENT", null, request.ip(), emailSent,
          "Test email sent to: " + testRequest.getEmail());

      if (emailSent) {
        return gson.toJson(Map.of(
            "success", true,
            "message", "Test email sent successfully",
            "email", testRequest.getEmail()
        ));
      } else {
        return gson.toJson(Map.of(
            "success", false,
            "error", "Could not send test email. Check the configuration and logs."
        ));
      }
    } catch (Exception e) {
      log.error("Error sending test email", e);
      return error(response, 500, "Internal server error");
    }
  }

  private boolean isValidEmail(String email) {
    return email != null && email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
  }

  private void logAuditEvent(String event, String userId, String clientIp, boolean success, String message) {
    try {
      if (config.isAuditEnabled()) {
        AuditLog auditLog = AuditLog.builder()
            .timestamp(Date.from(Instant.now()))
            .level("INFO")
            .event(event)
            .licenseKey(userId)
            .clientIp(clientIp)
            .success(success)
            .message(message)
            .build();

        database.saveAuditLog(auditLog);
      }
    } catch (Exception e) {
      log.error("Error saving audit log", e);
    }
  }

  @Getter
  @Setter
  public static class CreateFirstAdminRequest {
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private String password;
  }

  @Getter
  @Setter
  public static class TestEmailRequest {
    private String email;
  }
}
