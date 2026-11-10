package dev.neuralabs.auth.security;

import static spark.Spark.halt;

import com.google.gson.Gson;
import dev.neuralabs.auth.database.DatabaseInterface;
import dev.neuralabs.auth.model.User;
import dev.neuralabs.auth.util.JWTUtil;
import dev.neuralabs.auth.util.JWTUtil.JWTClaims;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import spark.Request;
import spark.Response;

@Slf4j
public class AuthorizationFilter {
  private static final String CLAIMS_ATTRIBUTE = "authClaims";

  private static final Set<String> PUBLIC_ROUTES = Set.of(
      "POST /verify",
      "POST /heartbeat",
      "POST /plugins/metadata",
      "GET /e2ee/public-key",
      "GET /plugins/signature/public-key",
      "POST /auth/login",
      "POST /auth/complete-registration",
      "POST /auth/request-password-reset",
      "POST /auth/reset-password",
      "GET /setup/status",
      "POST /setup/admin",
      "POST /setup/admin/default");

  private static final List<Pattern> ADMIN_ROUTES = List.of(
      Pattern.compile("[A-Z]+ /licenses(/(?!user/).*)?"),
      Pattern.compile("[A-Z]+ /license/.*"),
      Pattern.compile("GET /statistics"),
      Pattern.compile("GET /e2ee/stats"),
      Pattern.compile("(GET|POST) /plugins"),
      Pattern.compile("(PUT|DELETE) /plugins/[^/]+"),
      Pattern.compile("[A-Z]+ /email/.*"));

  private final String apiPrefix;
  private final DatabaseInterface database;
  private final Gson gson = new Gson();

  public AuthorizationFilter(String apiPrefix, DatabaseInterface database) {
    this.apiPrefix = apiPrefix;
    this.database = database;
  }

  public void filter(Request request, Response response) {
    if ("OPTIONS".equals(request.requestMethod())) {
      return;
    }

    String route = request.requestMethod() + " " + stripPrefix(request.pathInfo());
    if (PUBLIC_ROUTES.contains(route)) {
      return;
    }

    JWTClaims claims = authenticate(request);
    if (claims == null) {
      log.warn("Rejected unauthenticated request {} from {}", route, request.ip());
      halt(401, gson.toJson(Map.of("success", false, "error", "Authentication required")));
    }

    if (ADMIN_ROUTES.stream().anyMatch(p -> p.matcher(route).matches()) && !claims.isAdmin()) {
      log.warn("User {} denied admin route {} from {}", claims.getUserId(), route, request.ip());
      halt(403, gson.toJson(Map.of("success", false, "error", "Insufficient permissions")));
    }

    request.attribute(CLAIMS_ATTRIBUTE, claims);
  }

  public static JWTClaims claims(Request request) {
    return request.attribute(CLAIMS_ATTRIBUTE);
  }

  private JWTClaims authenticate(Request request) {
    String authHeader = request.headers("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return null;
    }

    JWTClaims claims = JWTUtil.validateToken(authHeader.substring(7));
    if (claims == null) {
      return null;
    }

    User user = database.findUserById(claims.getUserId());
    if (user == null || !user.canLogin()) {
      return null;
    }

    return JWTClaims.builder()
        .userId(user.getId())
        .email(user.getEmail())
        .role(user.getRole())
        .issuedAt(claims.getIssuedAt())
        .expiresAt(claims.getExpiresAt())
        .build();
  }

  private String stripPrefix(String path) {
    String collapsed = path.replaceAll("/+", "/").toLowerCase(Locale.ROOT);
    String normalized = collapsed.length() > 1 && collapsed.endsWith("/")
        ? collapsed.substring(0, collapsed.length() - 1)
        : collapsed;
    return normalized.startsWith(apiPrefix) ? normalized.substring(apiPrefix.length()) : normalized;
  }
}
