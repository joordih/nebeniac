package dev.neuralabs.auth.security;

import com.google.gson.Gson;
import dev.neuralabs.auth.util.JWTUtil;
import lombok.extern.slf4j.Slf4j;
import spark.Request;
import spark.Response;

import java.util.Map;

/**
 * Authorization filter for protecting admin endpoints.
 * SECURITY: Ensures only authenticated admin users can access sensitive operations.
 * 
 * Features:
 * - JWT token validation
 * - Role-based access control (RBAC)
 * - Automatic 401/403 responses for unauthorized access
 */
@Slf4j
public class AuthorizationFilter {

    private final Gson gson = new Gson();

    /**
     * Validates JWT token and checks for admin role.
     * 
     * @param request The HTTP request
     * @param response The HTTP response
     * @return true if authorized, false otherwise
     */
    public boolean requireAdmin(Request request, Response response) {
        return requireRole(request, response, "admin");
    }

    /**
     * Validates JWT token and checks for specific role.
     * 
     * @param request The HTTP request
     * @param response The HTTP response
     * @param requiredRole The role required to access the endpoint
     * @return true if authorized, false otherwise
     */
    public boolean requireRole(Request request, Response response, String requiredRole) {
        try {
            // Extract JWT from Authorization header
            String authHeader = request.headers("Authorization");
            
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Missing or invalid Authorization header from IP: {}", request.ip());
                response.status(401);
                response.type("application/json");
                response.body(gson.toJson(Map.of(
                    "success", false,
                    "error", "Authentication required",
                    "code", "MISSING_TOKEN"
                )));
                return false;
            }

            String token = authHeader.substring(7); // Remove "Bearer " prefix

            // Validate JWT token
            JWTUtil.JWTClaims claims = JWTUtil.validateToken(token);
            if (claims == null) {
                log.warn("Invalid JWT token from IP: {}", request.ip());
                response.status(401);
                response.type("application/json");
                response.body(gson.toJson(Map.of(
                    "success", false,
                    "error", "Invalid or expired token",
                    "code", "INVALID_TOKEN"
                )));
                return false;
            }

            // Extract user ID and role from token
            String userId = claims.getUserId();
            String role = claims.getRole();

            if (userId == null || role == null) {
                log.warn("Token missing user ID or role from IP: {}", request.ip());
                response.status(401);
                response.type("application/json");
                response.body(gson.toJson(Map.of(
                    "success", false,
                    "error", "Invalid token claims",
                    "code", "INVALID_CLAIMS"
                )));
                return false;
            }

            // Check if user has required role
            if (!role.equalsIgnoreCase(requiredRole)) {
                log.warn("User {} with role {} attempted to access {} endpoint from IP: {}", 
                    userId, role, requiredRole, request.ip());
                response.status(403);
                response.type("application/json");
                response.body(gson.toJson(Map.of(
                    "success", false,
                    "error", "Insufficient permissions",
                    "code", "FORBIDDEN",
                    "requiredRole", requiredRole
                )));
                return false;
            }

            // Store user info in request attributes for use in controller
            request.attribute("userId", userId);
            request.attribute("userRole", role);

            log.debug("User {} authorized for {} endpoint", userId, requiredRole);
            return true;

        } catch (Exception e) {
            log.error("Error during authorization check", e);
            response.status(500);
            response.type("application/json");
            response.body(gson.toJson(Map.of(
                "success", false,
                "error", "Authorization check failed",
                "code", "INTERNAL_ERROR"
            )));
            return false;
        }
    }

    /**
     * Validates JWT token without role check (authenticated user only).
     */
    public boolean requireAuthenticated(Request request, Response response) {
        try {
            String authHeader = request.headers("Authorization");
            
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                response.status(401);
                response.type("application/json");
                response.body(gson.toJson(Map.of(
                    "success", false,
                    "error", "Authentication required"
                )));
                return false;
            }

            String token = authHeader.substring(7);

            JWTUtil.JWTClaims claims = JWTUtil.validateToken(token);
            if (claims == null) {
                response.status(401);
                response.type("application/json");
                response.body(gson.toJson(Map.of(
                    "success", false,
                    "error", "Invalid or expired token"
                )));
                return false;
            }

            String userId = claims.getUserId();
            String role = claims.getRole();

            request.attribute("userId", userId);
            request.attribute("userRole", role);

            return true;

        } catch (Exception e) {
            log.error("Error during authentication check", e);
            response.status(500);
            response.type("application/json");
            response.body(gson.toJson(Map.of(
                "success", false,
                "error", "Authentication check failed"
            )));
            return false;
        }
    }

    /**
     * Helper method to get authenticated user ID from request.
     */
    public static String getAuthenticatedUserId(Request request) {
        return request.attribute("userId");
    }

    /**
     * Helper method to get authenticated user role from request.
     */
    public static String getAuthenticatedUserRole(Request request) {
        return request.attribute("userRole");
    }

    /**
     * Checks if the authenticated user is an admin.
     */
    public static boolean isAdmin(Request request) {
        String role = request.attribute("userRole");
        return role != null && role.equalsIgnoreCase("admin");
    }
}
