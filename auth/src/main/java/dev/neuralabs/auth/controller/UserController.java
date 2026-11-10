package dev.neuralabs.auth.controller;

import static dev.neuralabs.auth.controller.ControllerSupport.bearerClaims;
import static dev.neuralabs.auth.controller.ControllerSupport.error;

import com.google.gson.Gson;
import dev.neuralabs.auth.config.AuthConfig;
import dev.neuralabs.auth.database.DatabaseConnection;
import dev.neuralabs.auth.database.DatabaseInterface;
import dev.neuralabs.auth.model.AuditLog;
import dev.neuralabs.auth.model.User;
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
import java.util.*;

@Slf4j
public class UserController {
  private final DatabaseInterface database;
  private final Gson gson;
  private final EmailService emailService;

  public UserController() {
    this.database = DatabaseConnection.getInstance().getDatabase();
    this.gson = GsonUtil.build();

    this.emailService = new EmailService(AuthConfig.getInstance());
  }

  public String createUser(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = validateAdminRequest(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      CreateUserRequest createRequest = gson.fromJson(request.body(), CreateUserRequest.class);

      if (createRequest == null || createRequest.getEmail() == null) {
        return error(response, 400, "Email is required");
      }

      if (database.findUserByEmail(createRequest.getEmail()) != null) {
        return error(response, 409, "Email is already in use");
      }

      String verificationToken = PasswordUtil.generateToken();

      User user = User.builder()
          .email(createRequest.getEmail())
          .role(createRequest.getRole() != null ? createRequest.getRole() : "USER")
          .active(false)
          .emailVerified(false)
          .emailVerificationToken(verificationToken)
          .createdAt(Date.from(Instant.now()))
          .updatedAt(Date.from(Instant.now()))
          .createdBy(claims.getUserId())
          .permissions(createRequest.getPermissions() != null ? createRequest.getPermissions() : Arrays.asList("READ_PLUGINS", "DOWNLOAD_PLUGINS"))
          .build();

      database.saveUser(user);
      log.info("User saved to database: {}", user.getEmail());

      String userName = createRequest.getEmail().split("@")[0];
      log.info("Sending invitation email to: {} with token: {}", user.getEmail(), verificationToken);
      boolean emailSent = emailService.sendInvitationEmail(user.getEmail(), userName, verificationToken);
      log.info("Email send result: {}", emailSent);

      logAuditEvent("USER_CREATED", user.getId(), request.ip(), true,
          "User created by admin: " + claims.getUserId() + ", Email sent: " + emailSent);

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("user", sanitizeUser(user));
      responseData.put("emailSent", emailSent);
      responseData.put("message", emailSent ?
          "User created and invitation email sent" :
          "User created, but invitation email could not be sent");

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error creating user", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String getAllUsers(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = validateAdminRequest(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      List<User> users = database.findAllUsers();
      List<Map<String, Object>> sanitizedUsers = users.stream()
          .map(this::sanitizeUser)
          .toList();

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("users", sanitizedUsers);
      responseData.put("total", users.size());

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error fetching users", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String getUser(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = bearerClaims(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      String userId = request.params(":id");

      if (!claims.isAdmin() && !claims.getUserId().equals(userId)) {
        return error(response, 403, "Not authorized to view this user");
      }

      User user = database.findUserById(userId);
      if (user == null) {
        return error(response, 404, "User not found");
      }

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("user", sanitizeUser(user));

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error fetching user", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String updateUser(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = bearerClaims(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      String userId = request.params(":id");

      if (!claims.isAdmin() && !claims.getUserId().equals(userId)) {
        return error(response, 403, "Not authorized to update this user");
      }

      User existingUser = database.findUserById(userId);
      if (existingUser == null) {
        return error(response, 404, "User not found");
      }

      UpdateUserRequest updateRequest = gson.fromJson(request.body(), UpdateUserRequest.class);

      if (updateRequest.getFirstName() != null) {
        existingUser.setFirstName(updateRequest.getFirstName());
      }
      if (updateRequest.getLastName() != null) {
        existingUser.setLastName(updateRequest.getLastName());
      }
      if (updateRequest.getUsername() != null) {
        existingUser.setUsername(updateRequest.getUsername());
      }

      if (claims.isAdmin()) {
        if (updateRequest.getRole() != null) {
          existingUser.setRole(updateRequest.getRole());
        }
        if (updateRequest.getActive() != null) {
          existingUser.setActive(updateRequest.getActive());
        }
        if (updateRequest.getPermissions() != null) {
          existingUser.setPermissions(updateRequest.getPermissions());
        }
      }

      existingUser.setUpdatedAt(Date.from(Instant.now()));
      database.saveUser(existingUser);

      logAuditEvent("USER_UPDATED", userId, request.ip(), true,
          "User updated by: " + claims.getUserId());

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("user", sanitizeUser(existingUser));
      responseData.put("message", "User updated successfully");

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error updating user", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String deleteUser(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = validateAdminRequest(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      String userId = request.params(":id");

      if (claims.getUserId().equals(userId)) {
        return error(response, 400, "Cannot delete your own account");
      }

      User user = database.findUserById(userId);
      if (user == null) {
        return error(response, 404, "User not found");
      }

      database.deleteUser(userId);

      logAuditEvent("USER_DELETED", userId, request.ip(), true,
          "User deleted by admin: " + claims.getUserId());

      return gson.toJson(Map.of("success", true, "message", "User deleted successfully"));
    } catch (Exception e) {
      log.error("Error deleting user", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String resendInvitation(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = validateAdminRequest(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      String userId = request.params(":id");
      User user = database.findUserById(userId);

      if (user == null) {
        return error(response, 404, "User not found");
      }

      if (user.isEmailVerified()) {
        return error(response, 400, "User has already completed registration");
      }

      if (user.getEmailVerificationToken() == null) {
        user.setEmailVerificationToken(PasswordUtil.generateToken());
        database.saveUser(user);
      }

      String userName = user.getFullName() != null ? user.getFullName() : user.getEmail().split("@")[0];
      boolean emailSent = emailService.sendInvitationEmail(user.getEmail(), userName, user.getEmailVerificationToken());

      logAuditEvent("INVITATION_RESENT", userId, request.ip(), emailSent,
          "Invitation resent by admin: " + claims.getUserId());

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("emailSent", emailSent);
      responseData.put("message", emailSent ?
          "Invitation resent successfully" :
          "Error sending invitation");

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error resending invitation", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String searchUsers(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = validateAdminRequest(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      String query = request.queryParams("q");
      if (query == null) {
        query = "";
      }

      List<User> allUsers = database.findAllUsers();
      List<Map<String, Object>> matchingUsers = new ArrayList<>();

      String finalQuery = query.toLowerCase().trim();

      for (User user : allUsers) {
        boolean matches = false;

        if (user.getEmail() != null && user.getEmail().toLowerCase().contains(finalQuery)) {
          matches = true;
        } else if (user.getFirstName() != null && user.getFirstName().toLowerCase().contains(finalQuery)) {
          matches = true;
        } else if (user.getLastName() != null && user.getLastName().toLowerCase().contains(finalQuery)) {
          matches = true;
        } else if (user.getFullName() != null && user.getFullName().toLowerCase().contains(finalQuery)) {
          matches = true;
        } else if (user.getUsername() != null && user.getUsername().toLowerCase().contains(finalQuery)) {
          matches = true;
        } else if (finalQuery.isEmpty()) {
          matches = true;
        }

        if (matches) {
          Map<String, Object> userInfo = new HashMap<>();
          userInfo.put("id", user.getId());
          userInfo.put("email", user.getEmail());
          userInfo.put("firstName", user.getFirstName());
          userInfo.put("lastName", user.getLastName());
          userInfo.put("fullName", user.getFullName());
          userInfo.put("username", user.getUsername());
          userInfo.put("role", user.getRole());
          userInfo.put("active", user.isActive());
          userInfo.put("emailVerified", user.isEmailVerified());
          matchingUsers.add(userInfo);
        }
      }

      if (matchingUsers.size() > 20) {
        matchingUsers = matchingUsers.subList(0, 20);
      }

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("users", matchingUsers);
      responseData.put("total", matchingUsers.size());
      responseData.put("query", query);

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error searching users", e);
      return error(response, 500, "Internal server error");
    }
  }

  public String sendTestInvitation(Request request, Response response) {
    try {
      JWTUtil.JWTClaims claims = validateAdminRequest(request);
      if (claims == null) {
        return error(response, 401, "Unauthorized access");
      }

      @SuppressWarnings("unchecked")
      Map<String, String> requestData = gson.fromJson(request.body(), Map.class);
      String testEmail = requestData.get("email");

      if (testEmail == null || testEmail.isEmpty()) {
        return error(response, 400, "Email is required");
      }

      String testToken = PasswordUtil.generateToken();
      String userName = testEmail.split("@")[0];

      log.info("Sending test invitation email to: {}", testEmail);
      boolean emailSent = emailService.sendInvitationEmail(testEmail, userName, testToken);

      Map<String, Object> responseData = new HashMap<>();
      responseData.put("success", true);
      responseData.put("emailSent", emailSent);
      responseData.put("message", emailSent ?
          "Test email sent successfully" :
          "Error sending test email");
      responseData.put("testToken", testToken);

      return gson.toJson(responseData);
    } catch (Exception e) {
      log.error("Error sending test email", e);
      return error(response, 500, "Internal server error");
    }
  }

  private JWTUtil.JWTClaims validateAdminRequest(Request request) {
    JWTUtil.JWTClaims claims = bearerClaims(request);
    if (claims == null || !claims.isAdmin()) {
      return null;
    }
    return claims;
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
    sanitized.put("updatedAt", user.getUpdatedAt());
    sanitized.put("lastLoginAt", user.getLastLoginAt());
    sanitized.put("createdBy", user.getCreatedBy());
    sanitized.put("permissions", user.getPermissions());
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
  public static class CreateUserRequest {
    private String email;
    private String role;
    private List<String> permissions;
  }

  @Getter
  @Setter
  public static class UpdateUserRequest {
    private String firstName;
    private String lastName;
    private String username;
    private String role;
    private Boolean active;
    private List<String> permissions;
  }
}
