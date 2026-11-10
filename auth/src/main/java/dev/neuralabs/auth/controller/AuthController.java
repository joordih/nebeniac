package dev.neuralabs.auth.controller;

import static dev.neuralabs.auth.controller.ControllerSupport.error;

import com.google.gson.Gson;
import dev.neuralabs.auth.config.AuthConfig;
import dev.neuralabs.auth.database.DatabaseConnection;
import dev.neuralabs.auth.database.DatabaseInterface;
import dev.neuralabs.auth.model.AuditLog;
import dev.neuralabs.auth.model.User;
import dev.neuralabs.auth.model.UserSession;
import dev.neuralabs.auth.security.RateLimiter;
import dev.neuralabs.auth.service.EmailService;
import dev.neuralabs.auth.util.GsonUtil;
import dev.neuralabs.auth.util.JWTUtil;
import dev.neuralabs.auth.util.PasswordUtil;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import spark.Request;
import spark.Response;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class AuthController {
  private final DatabaseInterface database;
  private final Gson gson;
  private final EmailService emailService;
  private final AuthConfig config;
  private final RateLimiter loginRateLimiter;

  public AuthController() {
    this.database = DatabaseConnection.getInstance().getDatabase();
    this.config = AuthConfig.getInstance();
    this.gson = GsonUtil.build();

    this.emailService = new EmailService(config);
    this.loginRateLimiter = RateLimiter.Factory.forAuthentication();
  }

  public String login(Request request, Response response) {
    try {
      if (!loginRateLimiter.tryConsume(request.ip())) {
        log.warn("Login rate limit exceeded for IP: {}", request.ip());
        return error(response, 429, "Too many login attempts. Please try again later.");
      }

      LoginRequest loginRequest = gson.fromJson(request.body(), LoginRequest.class);

      if (loginRequest == null || loginRequest.getEmail() == null || loginRequest.getPassword() == null) {
        return error(response, 400, "Email and password are required");
      }

      User user = database.findUserByEmail(loginRequest.getEmail());
      if (user == null) {
        logAuditEvent("LOGIN_FAILED", null, request.ip(), false,
            "User not found: " + loginRequest.getEmail());
        return error(response, 401, "Invalid credentials");
      }

      if (!PasswordUtil.verifyPassword(loginRequest.getPassword(), user.getPasswordHash())) {
        logAuditEvent("LOGIN_FAILED", user.getId(), request.ip(), false, "Incorrect password");
        return error(response, 401, "Invalid credentials");
      }

      if (PasswordUtil.needsRehash(user.getPasswordHash())) {
        user.setPasswordHash(PasswordUtil.hashPassword(loginRequest.getPassword()));
        database.saveUser(user);
      }

      if (!user.canLogin()) {
        logAuditEvent("LOGIN_FAILED", user.getId(), request.ip(), false,
            "Inactive user or unverified email");
        return error(response, 403, "Account inactive or email not verified");
      }

      String token = JWTUtil.generateToken(user.getId(), user.getEmail(), user.getRole());

      UserSession session = UserSession.builder()
          .userId(user.getId())
          .token(token)
          .createdAt(Date.from(Instant.now()))
          .expiresAt(Date.from(Instant.now().plusMillis(config.getSessionTimeoutMillis())))
          .clientIp(request.ip())
          .userAgent(request.userAgent())
          .active(true)
          .build();

      database.saveUserSession(session);

      user.setLastLoginAt(Date.from(Instant.now()));
      database.saveUser(user);

      logAuditEvent("LOGIN_SUCCESS", user.getId(), request.ip(), true, "Login successful");

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("token", token);
      responseData.put("user", sanitizeUser(user));
      responseData.put("expiresIn", config.getSessionTimeoutMillis() / 1000);

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error during login", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String logout(Request request, Response response) {
    try {
      String authHeader = request.headers("Authorization");
      if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        return error(response, 401, "Token required");
      }

      String token = authHeader.substring(7);
      JWTUtil.JWTClaims claims = JWTUtil.validateToken(token);

      if (claims == null) {
        return error(response, 401, "Token invalid");
      }

      UserSession session = database.findUserSessionByToken(token);
      if (session != null) {
        database.deleteUserSession(session.getSessionId());
      }

      logAuditEvent("LOGOUT", claims.getUserId(), request.ip(), true, "Logout successful");

      return gson.toJson(Map.of("success", true, "message", "Logout successful"));
    } catch (Exception e) {
      log.error("Error during logout", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String completeRegistration(Request request, Response response) {
    try {
      CompleteRegistrationRequest regRequest = gson.fromJson(request.body(), CompleteRegistrationRequest.class);

      if (regRequest == null || regRequest.getToken() == null ||
          regRequest.getFirstName() == null || regRequest.getLastName() == null ||
          regRequest.getPassword() == null) {
        return error(response, 400, "All fields are required");
      }

      User user = database.findUserByEmailVerificationToken(regRequest.getToken());
      if (user == null) {
        return error(response, 404, "Verification token invalid or expired");
      }

      if (user.isEmailVerified()) {
        return error(response, 400, "User has already completed registration");
      }

      String passwordError = PasswordUtil.validatePassword(regRequest.getPassword(), config);
      if (passwordError != null) {
        return error(response, 400, passwordError);
      }

      user.setFirstName(regRequest.getFirstName());
      user.setLastName(regRequest.getLastName());
      user.setUsername(regRequest.getUsername());
      user.setPasswordHash(PasswordUtil.hashPassword(regRequest.getPassword()));
      user.setEmailVerified(true);
      user.setEmailVerificationToken(null);
      user.setActive(true);
      user.setUpdatedAt(Date.from(Instant.now()));

      database.saveUser(user);

      logAuditEvent("REGISTRATION_COMPLETED", user.getId(), request.ip(), true,
          "Registration completed successfully");

      return gson.toJson(Map.of("success", true, "message", "Registration completed successfully"));
    } catch (Exception e) {
      log.error("Error completing registration", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String requestPasswordReset(Request request, Response response) {
    try {
      PasswordResetRequest resetRequest = gson.fromJson(request.body(), PasswordResetRequest.class);

      if (resetRequest == null || resetRequest.getEmail() == null) {
        return error(response, 400, "Email is required");
      }

      User user = database.findUserByEmail(resetRequest.getEmail());
      if (user == null) {
        return gson.toJson(Map.of("success", true, "message",
            "If the email exists, you will receive instructions to reset your password"));
      }

      String resetToken = PasswordUtil.generateToken();
      user.setPasswordResetToken(resetToken);
      user.setPasswordResetExpires(
          Date.from(Instant.now().plusMillis(config.getPasswordResetTokenExpirationMillis())));
      database.saveUser(user);

      boolean emailSent = emailService.sendPasswordResetEmail(user.getEmail(), user.getFullName(), resetToken);

      logAuditEvent("PASSWORD_RESET_REQUESTED", user.getId(), request.ip(), emailSent,
          emailSent ? "Password reset email sent" : "Error sending password reset email");

      return gson.toJson(Map.of("success", true, "message",
          "If the email exists, you will receive instructions to reset your password"));
    } catch (Exception e) {
      log.error("Error requesting password reset", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String resetPassword(Request request, Response response) {
    try {
      ResetPasswordRequest resetRequest = gson.fromJson(request.body(), ResetPasswordRequest.class);

      if (resetRequest == null || resetRequest.getToken() == null || resetRequest.getNewPassword() == null) {
        return error(response, 400, "Token and new password are required");
      }

      User user = database.findUserByPasswordResetToken(resetRequest.getToken());
      if (user == null) {
        return error(response, 404, "Reset token invalid or expired");
      }

      if (user.getPasswordResetExpires() == null
          || user.getPasswordResetExpires().before(Date.from(Instant.now()))) {
        return error(response, 400, "Reset token expired");
      }

      String passwordError = PasswordUtil.validatePassword(resetRequest.getNewPassword(), config);
      if (passwordError != null) {
        return error(response, 400, passwordError);
      }

      user.setPasswordHash(PasswordUtil.hashPassword(resetRequest.getNewPassword()));
      user.setPasswordResetToken(null);
      user.setPasswordResetExpires(null);
      user.setUpdatedAt(Date.from(Instant.now()));

      database.saveUser(user);

      database.deleteUserSessionsByUserId(user.getId());

      logAuditEvent("PASSWORD_RESET", user.getId(), request.ip(), true, "Password reset successfully");

      return gson.toJson(Map.of("success", true, "message", "Password reset successfully"));
    } catch (Exception e) {
      log.error("Error resetting password", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String verifyToken(Request request, Response response) {
    try {
      String authHeader = request.headers("Authorization");

      if (authHeader == null || !authHeader.startsWith("Bearer ")) {
        return error(response, 401, "Token required");
      }

      String token = authHeader.substring(7);

      JWTUtil.JWTClaims claims = JWTUtil.validateToken(token);

      if (claims == null) {
        return error(response, 401, "Token invalid");
      }

      UserSession session = database.findUserSessionByToken(token);

      if (session == null || !session.isValid()) {
        User user = database.findUserById(claims.getUserId());
        if (user == null || !user.canLogin()) {
          return error(response, 401, "Invalid user");
        }

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("success", true);
        responseData.put("user", sanitizeUser(user));
        responseData.put("valid", true);
        responseData.put("warning", "Session not found in database, using JWT-only validation");

        return gson.toJson(responseData);
      }

      User user = database.findUserById(claims.getUserId());
      if (user == null || !user.canLogin()) {
        return error(response, 401, "Invalid user");
      }

      session.setLastAccessAt(Date.from(Instant.now()));
      database.saveUserSession(session);

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("user", sanitizeUser(user));
      responseData.put("valid", true);

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error verifying token", e);
      return error(response, 500, "Internal server error");
    }
  }

  private Map<String, Object> sanitizeUser(User user) {
    Map<String, Object> sanitized = new HashMap<>();
    sanitized.put("id", user.getId());
    sanitized.put("email", user.getEmail());
    sanitized.put("username", user.getUsername());
    sanitized.put("firstName", user.getFirstName());
    sanitized.put("lastName", user.getLastName());
    sanitized.put("fullName", user.getFullName());
    sanitized.put("role", user.getRole());
    sanitized.put("active", user.isActive());
    sanitized.put("emailVerified", user.isEmailVerified());
    sanitized.put("createdAt", user.getCreatedAt());
    sanitized.put("lastLoginAt", user.getLastLoginAt());
    return sanitized;
  }

  private void logAuditEvent(String event, String userId, String clientIp, boolean success, String message) {
    try {
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
    } catch (Exception e) {
      log.error("Error saving audit log", e);
    }
  }

  @Getter
  @Setter
  public static class LoginRequest {
    private String email;
    private String password;
  }

  @Getter
  @Setter
  public static class CompleteRegistrationRequest {
    private String token;
    private String firstName;
    private String lastName;
    private String username;
    private String password;
  }

  @Getter
  @Setter
  public static class PasswordResetRequest {
    private String email;
  }

  @Getter
  @Setter
  public static class ResetPasswordRequest {
    private String token;
    private String newPassword;
  }
}
