package dev.neuralabs.auth.util;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import dev.neuralabs.auth.config.AuthConfig;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

public class JWTUtil {

  private static final String ALGORITHM = "HmacSHA256";
  private static final Gson gson = new Gson();

  private static AuthConfig getConfig() {
    return AuthConfig.getInstance();
  }


  public static String generateToken(String userId, String email, String role) {
    try {

      JsonObject header = new JsonObject();
      header.addProperty("alg", "HS256");
      header.addProperty("typ", "JWT");
      String encodedHeader = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(gson.toJson(header).getBytes(StandardCharsets.UTF_8));


      AuthConfig config = getConfig();
      long now = Instant.now().getEpochSecond();
      long tokenValiditySeconds = config.getJwtExpirationMillis() / 1000;

      JsonObject payload = new JsonObject();
      payload.addProperty("sub", userId);
      payload.addProperty("email", email);
      payload.addProperty("role", role);
      payload.addProperty("iat", now);
      payload.addProperty("exp", now + tokenValiditySeconds);
      payload.addProperty("iss", config.getJwtIssuer());
      String encodedPayload = Base64.getUrlEncoder().withoutPadding()
          .encodeToString(gson.toJson(payload).getBytes(StandardCharsets.UTF_8));


      String data = encodedHeader + "." + encodedPayload;
      String signature = createSignature(data);

      return data + "." + signature;

    } catch (Exception e) {
      throw new RuntimeException("Error generando JWT", e);
    }
  }


  public static JWTClaims validateToken(String token) {
    try {
      String[] parts = token.split("\\.");
      if (parts.length != 3) {
        return null;
      }

      String header = parts[0];
      String payload = parts[1];
      String signature = parts[2];


      String data = header + "." + payload;
      String expectedSignature = createSignature(data);
      if (!signature.equals(expectedSignature)) {
        return null;
      }


      String decodedPayload = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
      JsonObject payloadObj = gson.fromJson(decodedPayload, JsonObject.class);


      long exp = payloadObj.get("exp").getAsLong();
      if (Instant.now().getEpochSecond() > exp) {
        return null;
      }

      return JWTClaims.builder()
          .userId(payloadObj.get("sub").getAsString())
          .email(payloadObj.get("email").getAsString())
          .role(payloadObj.get("role").getAsString())
          .issuedAt(new Date(payloadObj.get("iat").getAsLong() * 1000))
          .expiresAt(new Date(exp * 1000))
          .build();

    } catch (Exception e) {
      return null;
    }
  }

  private static String createSignature(String data) throws Exception {
    AuthConfig config = getConfig();
    Mac mac = Mac.getInstance(ALGORITHM);
    SecretKeySpec secretKeySpec = new SecretKeySpec(config.getJwtSecret().getBytes(StandardCharsets.UTF_8), ALGORITHM);
    mac.init(secretKeySpec);
    byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
  }


  public static class JWTClaims {
    private String userId;
    private String email;
    private String role;
    private Date issuedAt;
    private Date expiresAt;

    public static JWTClaimsBuilder builder() {
      return new JWTClaimsBuilder();
    }


    public String getUserId() {
      return userId;
    }

    public String getEmail() {
      return email;
    }

    public String getRole() {
      return role;
    }

    public Date getIssuedAt() {
      return issuedAt;
    }

    public Date getExpiresAt() {
      return expiresAt;
    }

    public boolean isAdmin() {
      return "ADMIN".equals(role);
    }

    public boolean isUser() {
      return "USER".equals(role);
    }

    public static class JWTClaimsBuilder {
      private String userId;
      private String email;
      private String role;
      private Date issuedAt;
      private Date expiresAt;

      public JWTClaimsBuilder userId(String userId) {
        this.userId = userId;
        return this;
      }

      public JWTClaimsBuilder email(String email) {
        this.email = email;
        return this;
      }

      public JWTClaimsBuilder role(String role) {
        this.role = role;
        return this;
      }

      public JWTClaimsBuilder issuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
        return this;
      }

      public JWTClaimsBuilder expiresAt(Date expiresAt) {
        this.expiresAt = expiresAt;
        return this;
      }

      public JWTClaims build() {
        JWTClaims claims = new JWTClaims();
        claims.userId = this.userId;
        claims.email = this.email;
        claims.role = this.role;
        claims.issuedAt = this.issuedAt;
        claims.expiresAt = this.expiresAt;
        return claims;
      }
    }
  }
}
