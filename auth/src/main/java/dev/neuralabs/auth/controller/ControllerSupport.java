package dev.neuralabs.auth.controller;

import com.google.gson.Gson;
import dev.neuralabs.auth.security.AuthorizationFilter;
import dev.neuralabs.auth.util.GsonUtil;
import dev.neuralabs.auth.util.JWTUtil;
import java.util.Map;
import spark.Request;
import spark.Response;

final class ControllerSupport {
  private static final Gson GSON = GsonUtil.build();

  private ControllerSupport() {}

  static String error(Response response, int status, String message) {
    response.status(status);
    return GSON.toJson(Map.of("success", false, "error", message));
  }

  static JWTUtil.JWTClaims bearerClaims(Request request) {
    return AuthorizationFilter.claims(request);
  }

  static boolean isEncryptedPayload(String body) {
    if (body == null || body.isEmpty()) {
      return false;
    }
    return body.contains("\"ciphertext\"") && body.contains("\"timestamp\"");
  }

  static String maskLicenseKey(String licenseKey) {
    if (licenseKey == null || licenseKey.length() < 8) {
      return "***";
    }
    return licenseKey.substring(0, 4) + "***" + licenseKey.substring(licenseKey.length() - 4);
  }
}
