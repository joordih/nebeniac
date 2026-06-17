package dev.neuralabs.auth.database;

import dev.neuralabs.auth.model.*;

import java.util.List;
import java.util.Map;


public interface DatabaseInterface {


  void initialize();

  boolean isHealthy();

  void shutdown();


  License findLicenseByKey(String licenseKey);

  List<License> findAllLicenses();

  void saveLicense(License license);

  void deleteLicense(String licenseKey);


  Plugin findPluginById(String pluginId);

  List<Plugin> findAllPlugins();

  void savePlugin(Plugin plugin);

  void deletePlugin(String pluginId);


  List<Activation> findActivationsByLicenseKey(String licenseKey);

  void saveActivation(Activation activation);

  void removeActivation(String licenseKey, String hardwareFingerprint);


  Session findSessionByToken(String token);

  void saveSession(Session session);

  void removeSession(String token);


  void saveAuditLog(AuditLog auditLog);

  List<AuditLog> findAuditLogs(int limit);


  Map<String, Object> getStatistics();


  void saveUser(User user);

  User findUserById(String userId);

  User findUserByEmail(String email);

  User findUserByUsername(String username);

  User findUserByEmailVerificationToken(String token);

  User findUserByPasswordResetToken(String token);

  List<User> findAllUsers();

  void deleteUser(String userId);


  void saveUserSession(UserSession session);

  UserSession findUserSessionByToken(String token);

  UserSession findUserSessionById(String sessionId);

  List<UserSession> findUserSessionsByUserId(String userId);

  void deleteUserSession(String sessionId);

  void deleteUserSessionsByUserId(String userId);

  void cleanupExpiredUserSessions();
}
