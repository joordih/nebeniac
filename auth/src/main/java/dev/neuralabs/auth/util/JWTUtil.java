package dev.neuralabs.auth.util;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import dev.neuralabs.auth.config.AuthConfig;
import lombok.Builder;
import lombok.Getter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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

      JsonObject header = decodeSegment(parts[0]);
      if (!header.has("alg") || !"HS256".equals(header.get("alg").getAsString())) {
        return null;
      }

      byte[] expectedSignature = createSignature(parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
      if (!MessageDigest.isEqual(parts[2].getBytes(StandardCharsets.US_ASCII), expectedSignature)) {
        return null;
      }

      JsonObject payloadObj = decodeSegment(parts[1]);
      if (!payloadObj.has("exp") || !payloadObj.has("iss")
          || !getConfig().getJwtIssuer().equals(payloadObj.get("iss").getAsString())) {
        return null;
      }

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

  private static JsonObject decodeSegment(String segment) {
    String json = new String(Base64.getUrlDecoder().decode(segment), StandardCharsets.UTF_8);
    return gson.fromJson(json, JsonObject.class);
  }

  private static String createSignature(String data) throws Exception {
    AuthConfig config = getConfig();
    Mac mac = Mac.getInstance(ALGORITHM);
    SecretKeySpec secretKeySpec = new SecretKeySpec(config.getJwtSecret().getBytes(StandardCharsets.UTF_8), ALGORITHM);
    mac.init(secretKeySpec);
    byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
  }

  @Getter
  @Builder
  public static class JWTClaims {
    private String userId;
    private String email;
    private String role;
    private Date issuedAt;
    private Date expiresAt;

    public boolean isAdmin() {
      return "ADMIN".equalsIgnoreCase(role);
    }
  }
}
