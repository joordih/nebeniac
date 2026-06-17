package dev.neuralabs.auth.service;

import dev.neuralabs.auth.config.AuthConfig;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;

@Slf4j
public class EmailService {

  private static final String GMAIL_API_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send";
  private static final String OAUTH_TOKEN_URL = "https://oauth2.googleapis.com/token";

  private final String clientId;
  private final String clientSecret;
  private final String refreshToken;
  private final String fromEmail;
  private final AuthConfig config;

  private String accessToken;
  private long tokenExpiresAt;

  public EmailService(String clientId, String clientSecret, String refreshToken, String fromEmail) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.refreshToken = refreshToken;
    this.fromEmail = fromEmail;
    this.config = null;
  }

  public EmailService(AuthConfig config) {
    this.config = config;
    this.clientId = config.getGoogleOAuthClientId();
    this.clientSecret = config.getGoogleOAuthClientSecret();
    this.refreshToken = config.getGoogleOAuthRefreshToken();
    this.fromEmail = config.getEmailFrom();
  }

  public boolean sendInvitationEmail(String toEmail, String userName, String verificationToken) {
    try {
      String subject = "Invitation to Nebeniac - Complete your registration";
      String htmlBody = createInvitationEmailTemplate(userName, verificationToken);

      return sendEmail(toEmail, subject, htmlBody);

    } catch (Exception e) {
      log.error("Error sending invitation email to {}", toEmail, e);
      return false;
    }
  }

  public boolean sendPasswordResetEmail(String toEmail, String userName, String resetToken) {
    try {
      String subject = "Nebeniac - Reset password";
      String htmlBody = createPasswordResetEmailTemplate(userName, resetToken);

      return sendEmail(toEmail, subject, htmlBody);

    } catch (Exception e) {
      log.error("Error sending password reset email to {}", toEmail, e);
      return false;
    }
  }

  public boolean sendWelcomeAdminEmail(String toEmail, String userName) {
    try {
      String subject = "Bienvenido a Nebeniac - Cuenta de Administrador Creada";
      String htmlBody = createWelcomeAdminEmailTemplate(userName);

      return sendEmail(toEmail, subject, htmlBody);

    } catch (Exception e) {
      log.error("Error sending welcome email to administrator {}", toEmail, e);
      return false;
    }
  }

  public boolean sendTestEmail(String toEmail) {
    try {
      String subject = "Nebeniac - Test Email";
      String htmlBody = createTestEmailTemplate();

      log.info("Sending test email to: {}", toEmail);
      return sendEmail(toEmail, subject, htmlBody);

    } catch (Exception e) {
      log.error("Error sending test email to {}", toEmail, e);
      return false;
    }
  }

  public EmailStatus getEmailStatus() {
    EmailStatus status = new EmailStatus();
    status.enabled = config.isEmailEnabled();
    status.configured = config.isEmailConfigured();
    status.provider = config.getEmailProvider().toString();
    status.fromEmail = config.getEmailFrom();

    if (config.getEmailProvider() == AuthConfig.EmailProvider.GMAIL_API) {
      status.googleOAuthConfigured = config.isGoogleOAuthConfigured();
      status.clientIdConfigured = !config.getGoogleOAuthClientId().isEmpty();
      status.clientSecretConfigured = !config.getGoogleOAuthClientSecret().isEmpty();
      status.refreshTokenConfigured = !config.getGoogleOAuthRefreshToken().isEmpty();
    }

    return status;
  }

  public static class EmailStatus {
    public boolean enabled;
    public boolean configured;
    public String provider;
    public String fromEmail;
    public boolean googleOAuthConfigured;
    public boolean clientIdConfigured;
    public boolean clientSecretConfigured;
    public boolean refreshTokenConfigured;
  }

  private boolean sendEmail(String toEmail, String subject, String htmlBody) {
    try {
      log.info("Intentando enviar email a: {} con asunto: {}", toEmail, subject);

      if (!config.isEmailConfigured()) {
        log.warn("Email not configured. Skipping email send to: {}", toEmail);
        log.warn("Email enabled: {}, Provider: {}, From: {}",
            config.isEmailEnabled(), config.getEmailProvider(), config.getEmailFrom());
        return false;
      }

      log.info("Email configuration verified. Fetching access token...");

      if (!ensureValidAccessToken()) {
        log.error("Could not obtain valid access token for send to: {}", toEmail);
        return false;
      }

      log.info("Access token obtenido correctamente. Preparando mensaje...");

      String message = createRFC2822Message(toEmail, subject, htmlBody);
      String encodedMessage = Base64.getUrlEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8));

      String requestBody = "{\"raw\":\"" + encodedMessage + "\"}";

      HttpClient client = HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(30))
          .build();

      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(GMAIL_API_URL))
          .header("Authorization", "Bearer " + accessToken)
          .header("Content-Type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .build();

      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 200) {
        log.info("Email sent successfully to {}", toEmail);
        return true;
      } else {
        log.error("Error sending email to {}. Status: {}, Body: {}", toEmail, response.statusCode(),
            response.body());

        String responseBody = response.body();
        if (responseBody.contains("insufficientPermissions")) {
          log.error(
              "Insufficient permissions. Verify that the 'https://www.googleapis.com/auth/gmail.send' scope is authorized");
        } else if (responseBody.contains("quotaExceeded")) {
          log.error("Gmail API quota exceeded. Wait before sending more emails");
        } else if (responseBody.contains("invalidRecipient")) {
          log.error("Invalid recipient: {}. Verify that the email address is valid", toEmail);
        } else if (responseBody.contains("userNotFound")) {
          log.error("User not found. Verify OAuth configuration");
        }

        return false;
      }

    } catch (Exception e) {
      log.error("Error sending email to {}", toEmail, e);
      return false;
    }
  }

  private boolean ensureValidAccessToken() {

    if (accessToken != null && System.currentTimeMillis() < (tokenExpiresAt - 300000)) {
      return true;
    }

    try {

      String requestBody = "grant_type=refresh_token" +
          "&refresh_token=" + URLEncoder.encode(refreshToken, StandardCharsets.UTF_8) +
          "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8) +
          "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);

      HttpClient client = HttpClient.newBuilder()
          .connectTimeout(Duration.ofSeconds(30))
          .build();

      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(OAUTH_TOKEN_URL))
          .header("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
          .build();

      HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() == 200) {

        String responseBody = response.body();
        String accessTokenValue = extractJsonValue(responseBody, "access_token");
        String expiresInValue = extractJsonValue(responseBody, "expires_in");

        if (accessTokenValue != null && expiresInValue != null) {
          this.accessToken = accessTokenValue;
          this.tokenExpiresAt = System.currentTimeMillis() + (Long.parseLong(expiresInValue) * 1000);
          log.info("Access token renewed successfully");
          return true;
        }
      }

      log.error("Error renovando access token. Status: {}, Body: {}", response.statusCode(), response.body());
      return false;

    } catch (Exception e) {
      log.error("Error renovando access token", e);
      return false;
    }
  }

  private String extractJsonValue(String json, String key) {

    String searchKey = "\"" + key + "\"";
    int keyIndex = json.indexOf(searchKey);
    if (keyIndex == -1)
      return null;

    int colonIndex = json.indexOf(":", keyIndex);
    if (colonIndex == -1)
      return null;

    int valueStart = colonIndex + 1;
    while (valueStart < json.length() && (json.charAt(valueStart) == ' ' || json.charAt(valueStart) == '"')) {
      valueStart++;
    }

    int valueEnd = valueStart;
    while (valueEnd < json.length() && json.charAt(valueEnd) != '"' && json.charAt(valueEnd) != ','
        && json.charAt(valueEnd) != '}') {
      valueEnd++;
    }

    return json.substring(valueStart, valueEnd);
  }

  private String createRFC2822Message(String toEmail, String subject, String htmlBody) {
    return "From: " + fromEmail + "\r\n" +
        "To: " + toEmail + "\r\n" +
        "Subject: " + subject + "\r\n" +
        "Content-Type: text/html; charset=UTF-8\r\n" +
        "Content-Transfer-Encoding: base64\r\n" +
        "\r\n" +
        Base64.getEncoder().encodeToString(htmlBody.getBytes(StandardCharsets.UTF_8));
  }

  private String createInvitationEmailTemplate(String userName, String verificationToken) {
    String baseUrl = config != null ? config.getBaseUrl()
        : System.getProperty("app.base.url", "http://localhost:3000");
    String verificationUrl = baseUrl + "/complete-registration?token=" + verificationToken;

    return "<!DOCTYPE html>" +
        "<html>" +
        "<head><meta charset='UTF-8'><title>Invitation to Nebeniac</title></head>" +
        "<body style='font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #0a0a0a; color: #fafafa;'>"
        +
        "<div style='background-color: #1a1a1a; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; overflow: hidden;'>"
        +
        "<div style='padding: 32px; text-align: center; background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);'>"
        +
        "<h1 style='margin: 0; font-size: 28px; font-weight: 700; color: white;'>🛡️ Nebeniac</h1>" +
        "<p style='margin: 8px 0 0 0; font-size: 16px; color: rgba(255, 255, 255, 0.9);'>Plugin Protection System</p>"
        +
        "</div>" +
        "<div style='padding: 32px; background-color: #1a1a1a;'>" +
        "<h2 style='color: #fafafa; margin-top: 0; font-size: 24px; font-weight: 600;'>Welcome to Nebeniac!</h2>"
        +
        "<p style='color: #a1a1aa; line-height: 1.6; margin: 16px 0;'>Hola <strong style='color: #fafafa;'>"
        + userName + "</strong>,</p>" +
        "<p style='color: #a1a1aa; line-height: 1.6; margin: 16px 0;'>You have been invited to join Nebeniac, our Minecraft plugin protection system. To complete your registration, click the button below:</p>"
        +
        "<div style='text-align: center; margin: 32px 0;'>" +
        "<a href='" + verificationUrl
        + "' style='background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%); color: white; padding: 16px 32px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block; transition: all 0.2s;'>Completar Registro</a>"
        +
        "</div>" +
        "<div style='background-color: #262626; border: 1px solid #404040; border-radius: 8px; padding: 20px; margin: 24px 0;'>"
        +
        "<h3 style='color: #fafafa; margin-top: 0; font-size: 18px; font-weight: 600;'>Once you complete your registration, you will be able to:</h3>"
        +
        "<ul style='color: #a1a1aa; line-height: 1.6; margin: 0; padding-left: 20px;'>" +
        "<li>Download protected plugins with automatic licenses</li>" +
        "<li>Manage your plugin licenses</li>" +
        "<li>Access your personalized user dashboard</li>" +
        "</ul>" +
        "</div>" +
        "<div style='border-top: 1px solid #404040; padding-top: 24px; margin-top: 32px;'>" +
        "<p style='color: #71717a; font-size: 14px; margin: 8px 0;'>If you did not request this invitation, you can ignore this email.</p>"
        +
        "<p style='color: #71717a; font-size: 14px; margin: 8px 0;'>This link will expire in 24 hours.</p>" +
        "</div>" +
        "</div>" +
        "</div>" +
        "</body>" +
        "</html>";
  }

  private String createPasswordResetEmailTemplate(String userName, String resetToken) {
    String baseUrl = config != null ? config.getBaseUrl()
        : System.getProperty("app.base.url", "http://localhost:3000");
    String resetUrl = baseUrl + "/reset-password?token=" + resetToken;

    return "<!DOCTYPE html>" +
        "<html>" +
        "<head><meta charset='UTF-8'><title>Reset Password - Nebeniac</title></head>" +
        "<body style='font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #0a0a0a; color: #fafafa;'>"
        +
        "<div style='background-color: #1a1a1a; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; overflow: hidden;'>"
        +
        "<div style='padding: 32px; text-align: center; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);'>"
        +
        "<h1 style='margin: 0; font-size: 28px; font-weight: 700; color: white;'>🛡️ Nebeniac</h1>" +
        "<p style='margin: 8px 0 0 0; font-size: 16px; color: rgba(255, 255, 255, 0.9);'>Reset Password</p>"
        +
        "</div>" +
        "<div style='padding: 32px; background-color: #1a1a1a;'>" +
        "<h2 style='color: #fafafa; margin-top: 0; font-size: 24px; font-weight: 600;'>Reset your password</h2>"
        +
        "<p style='color: #a1a1aa; line-height: 1.6; margin: 16px 0;'>Hola <strong style='color: #fafafa;'>"
        + userName + "</strong>,</p>" +
        "<p style='color: #a1a1aa; line-height: 1.6; margin: 16px 0;'>We received a request to reset your account password. Click the button below to create a new password:</p>"
        +
        "<div style='text-align: center; margin: 32px 0;'>" +
        "<a href='" + resetUrl
        + "' style='background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; padding: 16px 32px; text-decoration: none; border-radius: 8px; font-weight: 600; display: inline-block;'>Reset Password</a>"
        +
        "</div>" +
        "<div style='border-top: 1px solid #404040; padding-top: 24px; margin-top: 32px;'>" +
        "<p style='color: #71717a; font-size: 14px; margin: 8px 0;'>If you did not request this reset, you can safely ignore this email.</p>"
        +
        "<p style='color: #71717a; font-size: 14px; margin: 8px 0;'>This link will expire in 1 hour for security.</p>"
        +
        "</div>" +
        "</div>" +
        "</div>" +
        "</body>" +
        "</html>";
  }

  private String createWelcomeAdminEmailTemplate(String userName) {
    return "<!DOCTYPE html>" +
        "<html>" +
        "<head><meta charset='UTF-8'><title>Bienvenido a Nebeniac</title></head>" +
        "<body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>" +
        "<div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0;'>"
        +
        "<h1 style='margin: 0; font-size: 28px;'>🛡️ Nebeniac</h1>" +
        "<p style='margin: 10px 0 0 0; font-size: 16px;'>Plugin Protection System</p>" +
        "</div>" +
        "<div style='background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;'>"
        +
        "<h2 style='color: #333; margin-top: 0;'>Welcome, Administrator!</h2>" +
        "<p style='color: #666; line-height: 1.6;'>Hola <strong>" + userName + "</strong>,</p>" +
        "<p style='color: #666; line-height: 1.6;'>Your administrator account has been created successfully in Nebeniac. You now have full access to the plugin protection system.</p>"
        +
        "<div style='background: #e3f2fd; padding: 20px; border-radius: 5px; margin: 20px 0;'>" +
        "<h3 style='color: #1976d2; margin-top: 0;'>🔧 Administrator Features</h3>" +
        "<ul style='color: #666; line-height: 1.6; margin: 0; padding-left: 20px;'>" +
        "<li>Full user and permission management</li>" +
        "<li>Plugin and license administration</li>" +
        "<li>Authentication system configuration</li>" +
        "<li>Access to audit logs and statistics</li>" +
        "<li>Security policy configuration</li>" +
        "</ul>" +
        "</div>" +
        "<div style='background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;'>" +
        "<p style='color: #856404; margin: 0; font-weight: bold;'>⚠️ Security Recommendations:</p>" +
        "<ul style='color: #856404; line-height: 1.6; margin: 10px 0 0 0; padding-left: 20px;'>" +
        "<li>Change your password regularly</li>" +
        "<li>Enable two-factor authentication when available</li>" +
        "<li>Review access logs regularly</li>" +
        "<li>Keep the system up to date</li>" +
        "</ul>" +
        "</div>" +
        "<p style='color: #666; line-height: 1.6;'>If you have any questions or need assistance, please contact the support team.</p>"
        +
        "<p style='color: #999; font-size: 14px; margin-top: 30px;'>This email was sent automatically by the Nebeniac system.</p>"
        +
        "</div>" +
        "</body>" +
        "</html>";
  }

  private String createTestEmailTemplate() {
    return "<!DOCTYPE html>" +
        "<html>" +
        "<head><meta charset='UTF-8'><title>Test Email - Nebeniac</title></head>" +
        "<body style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;'>" +
        "<div style='background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; border-radius: 10px 10px 0 0;'>"
        +
        "<h1 style='margin: 0; font-size: 28px;'>🛡️ Nebeniac</h1>" +
        "<p style='margin: 10px 0 0 0; font-size: 16px;'>Test Email</p>" +
        "</div>" +
        "<div style='background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;'>"
        +
        "<h2 style='color: #333; margin-top: 0;'>✅ Email Configuration Successful</h2>" +
        "<p style='color: #666; line-height: 1.6;'>Congratulations! If you are reading this email, the Nebeniac email service is configured correctly.</p>"
        +
        "<div style='background: #d4edda; padding: 20px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #28a745;'>"
        +
        "<h3 style='color: #155724; margin-top: 0;'>📧 Test Details</h3>" +
        "<ul style='color: #155724; line-height: 1.6; margin: 0; padding-left: 20px;'>" +
        "<li>Provider: Gmail API</li>" +
        "<li>Authentication: OAuth 2.0</li>" +
        "<li>Status: Working correctly</li>" +
        "<li>Fecha: " + new Date() + "</li>" +
        "</ul>" +
        "</div>" +
        "<p style='color: #666; line-height: 1.6;'>You can now send invitation emails, password recovery emails, and system notifications without issues.</p>"
        +
        "<div style='background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0;'>" +
        "<p style='color: #856404; margin: 0;'><strong>Note:</strong> In a development environment, Google OAuth may restrict sending emails to unverified addresses.</p>"
        +
        "</div>" +
        "<p style='color: #999; font-size: 14px; margin-top: 30px;'>This is an automatic test email from the Nebeniac system.</p>"
        +
        "</div>" +
        "</body>" +
        "</html>";
  }
}
