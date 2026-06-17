package dev.neuralabs.auth.controller;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import dev.neuralabs.auth.config.AuthConfig;
import dev.neuralabs.auth.database.DatabaseConnection;
import dev.neuralabs.auth.database.DatabaseInterface;
import dev.neuralabs.auth.model.AuditLog;
import dev.neuralabs.auth.model.User;
import dev.neuralabs.auth.service.EmailService;
import dev.neuralabs.auth.util.PasswordUtil;
import lombok.extern.slf4j.Slf4j;
import spark.Request;
import spark.Response;

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

  public SetupController() {
    this.database = DatabaseConnection.getInstance().getDatabase();
    this.config = AuthConfig.getInstance();
    this.gson = new GsonBuilder()
        .setDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
        .create();
    this.emailService = new EmailService(config);
  }


  public String createFirstAdmin(Request request, Response response) {
    response.type("application/json");

    try {

      if (!database.findAllUsers().isEmpty()) {
        return error(response, 403, "The system already has users configured. This endpoint is only for initial setup.");
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


      String passwordError = validatePassword(adminRequest.getPassword());
      if (passwordError != null) {
        return error(response, 400, passwordError);
      }


      User admin = User.builder()
          .id(new org.bson.types.ObjectId().toHexString())
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


      database.saveUser(admin);


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
    response.type("application/json");

    try {
      boolean hasUsers = !database.findAllUsers().isEmpty();
      boolean isHealthy = database.isHealthy();

      return gson.toJson(Map.of(
          "success", true,
          "setupComplete", hasUsers,
          "hasUsers", hasUsers,
          "databaseHealthy", isHealthy,
          "needsInitialSetup", !hasUsers,
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
    response.type("application/json");

    try {

      if (!config.isDevMode()) {
        return error(response, 403, "This endpoint is only available in development mode");
      }


      if (!database.findAllUsers().isEmpty()) {
        return error(response, 403, "System already has users configured");
      }


      User admin = User.builder()
          .id(new org.bson.types.ObjectId().toHexString())
          .email("admin@nebeniac.com")
          .username("admin")
          .firstName("Administrator")
          .lastName("System")
          .passwordHash(PasswordUtil.hashPassword("admin123"))
          .role("ADMIN")
          .active(true)
          .emailVerified(true)
          .createdAt(Date.from(Instant.now()))
          .updatedAt(Date.from(Instant.now()))
          .permissions(List.of("ALL"))
          .build();

      database.saveUser(admin);

      log.warn("Default administrator user created for development: {}", admin.getEmail());

      return gson.toJson(Map.of(
          "success", true,
          "message", "Default administrator user created",
          "credentials", Map.of(
              "email", "admin@nebeniac.com",
              "password", "admin123"
          ),
          "warning", "CHANGE PASSWORD IMMEDIATELY! This is an insecure default password."
      ));

    } catch (Exception e) {
      log.error("Error creating default administrator", e);
      return error(response, 500, "Internal server error");
    }
  }


  public String getEmailStatus(Request request, Response response) {
    response.type("application/json");

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
    response.type("application/json");

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

  private String validatePassword(String password) {
    if (password == null || password.length() < config.getPasswordMinLength()) {
      return "Password must be at least " + config.getPasswordMinLength() + " characters";
    }

    if (config.isPasswordRequireUppercase() && !password.matches(".*[A-Z].*")) {
      return "Password must contain at least one uppercase letter";
    }

    if (config.isPasswordRequireLowercase() && !password.matches(".*[a-z].*")) {
      return "Password must contain at least one lowercase letter";
    }

    if (config.isPasswordRequireNumbers() && !password.matches(".*\\d.*")) {
      return "Password must contain at least one number";
    }

    if (config.isPasswordRequireSpecialChars() && !password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*")) {
      return "Password must contain at least one special character";
    }

    return null;
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


  private String error(Response response, int status, String message) {
    response.status(status);
    return gson.toJson(Map.of("success", false, "error", message));
  }


  public static class CreateFirstAdminRequest {
    private String email;
    private String username;
    private String firstName;
    private String lastName;
    private String password;

    public String getEmail() {
      return email;
    }

    public void setEmail(String email) {
      this.email = email;
    }

    public String getUsername() {
      return username;
    }

    public void setUsername(String username) {
      this.username = username;
    }

    public String getFirstName() {
      return firstName;
    }

    public void setFirstName(String firstName) {
      this.firstName = firstName;
    }

    public String getLastName() {
      return lastName;
    }

    public void setLastName(String lastName) {
      this.lastName = lastName;
    }

    public String getPassword() {
      return password;
    }

    public void setPassword(String password) {
      this.password = password;
    }
  }

  public static class TestEmailRequest {
    private String email;

    public String getEmail() {
      return email;
    }

    public void setEmail(String email) {
      this.email = email;
    }
  }
}
