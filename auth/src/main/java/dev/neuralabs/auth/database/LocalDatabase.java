package dev.neuralabs.auth.database;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import dev.neuralabs.auth.model.*;
import dev.neuralabs.auth.util.GsonUtil;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.Collection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Slf4j
public class LocalDatabase implements DatabaseInterface {
  private static LocalDatabase instance;
  private final Gson gson;
  private final Path dataDirectory;

  private final Map<String, License> licenses = new ConcurrentHashMap<>();
  private final Map<String, Plugin> plugins = new ConcurrentHashMap<>();
  private final Map<String, List<Activation>> activations = new ConcurrentHashMap<>();
  private final Map<String, Session> sessions = new ConcurrentHashMap<>();
  private final List<AuditLog> auditLogs = Collections.synchronizedList(new ArrayList<>());
  private final Map<String, User> users = new ConcurrentHashMap<>();
  private final Map<String, UserSession> userSessions = new ConcurrentHashMap<>();

  private final AtomicLong licenseIdCounter = new AtomicLong(1);
  private final AtomicLong pluginIdCounter = new AtomicLong(1);
  private final AtomicLong activationIdCounter = new AtomicLong(1);
  private final AtomicLong auditLogIdCounter = new AtomicLong(1);

  private static final String LICENSES_FILE = "licenses.json";
  private static final String PLUGINS_FILE = "plugins.json";
  private static final String ACTIVATIONS_FILE = "activations.json";
  private static final String SESSIONS_FILE = "sessions.json";
  private static final String AUDIT_LOGS_FILE = "audit_logs.json";
  private static final String COUNTERS_FILE = "counters.json";
  private static final String USERS_FILE = "users.json";
  private static final String USER_SESSIONS_FILE = "user_sessions.json";

  private LocalDatabase() {
    this.gson = GsonUtil.buildPretty();

    String configuredDir = System.getenv("NEBENIAC_DATA_DIR");
    this.dataDirectory = configuredDir != null && !configuredDir.isBlank()
        ? Paths.get(configuredDir.trim())
        : Paths.get(System.getProperty("user.home"), ".nebeniac", "data");
    try {
      Files.createDirectories(dataDirectory);
    } catch (IOException e) {
      log.error("Error creating data directory", e);
      throw new RuntimeException("Could not create data directory", e);
    }
  }

  public static synchronized LocalDatabase getInstance() {
    if (instance == null) {
      instance = new LocalDatabase();
    }
    return instance;
  }

  public void initialize() {
    log.info("Initializing local database at: {}", dataDirectory);
    loadAllData();
    createDefaultLicenses();
    log.info("Local database initialized successfully");
  }

  private void loadAllData() {
    loadMap(LICENSES_FILE, new TypeToken<Map<String, License>>() {}.getType(), licenses, "licenses");
    loadMap(PLUGINS_FILE, new TypeToken<Map<String, Plugin>>() {}.getType(), plugins, "plugins");
    loadMap(ACTIVATIONS_FILE, new TypeToken<Map<String, List<Activation>>>() {}.getType(), activations, "activations");
    loadMap(SESSIONS_FILE, new TypeToken<Map<String, Session>>() {}.getType(), sessions, "sessions");
    loadList(AUDIT_LOGS_FILE, new TypeToken<List<AuditLog>>() {}.getType(), auditLogs, "audit logs");
    loadMap(USERS_FILE, new TypeToken<Map<String, User>>() {}.getType(), users, "users");
    loadMap(USER_SESSIONS_FILE, new TypeToken<Map<String, UserSession>>() {}.getType(), userSessions, "user sessions");
    loadCounters();
  }

  @SuppressWarnings("unchecked")
  private <T> void loadMap(String fileName, Type type, Map<String, T> target, String label) {
    Path file = dataDirectory.resolve(fileName);
    if (!Files.exists(file)) return;
    try {
      Map<String, T> loaded = gson.fromJson(Files.readString(file), type);
      if (loaded != null) target.putAll(loaded);
      log.info("Loaded {} {}", target.size(), label);
    } catch (IOException e) {
      log.error("Error loading {}", label, e);
    }
  }

  private <T> void loadList(String fileName, Type type, Collection<T> target, String label) {
    Path file = dataDirectory.resolve(fileName);
    if (!Files.exists(file)) return;
    try {
      List<T> loaded = gson.fromJson(Files.readString(file), type);
      if (loaded != null) target.addAll(loaded);
      log.info("Loaded {} {}", target.size(), label);
    } catch (IOException e) {
      log.error("Error loading {}", label, e);
    }
  }

  private void loadCounters() {
    Path file = dataDirectory.resolve(COUNTERS_FILE);
    if (Files.exists(file)) {
      try {
        String json = Files.readString(file);
        Type type = new TypeToken<Map<String, Long>>() {
        }.getType();
        Map<String, Long> counters = gson.fromJson(json, type);
        if (counters != null) {
          licenseIdCounter.set(counters.getOrDefault("licenseId", 1L));
          pluginIdCounter.set(counters.getOrDefault("pluginId", 1L));
          activationIdCounter.set(counters.getOrDefault("activationId", 1L));
          auditLogIdCounter.set(counters.getOrDefault("auditLogId", 1L));
        }
      } catch (IOException e) {
        log.error("Error loading counters", e);
      }
    }
  }

  private void createDefaultLicenses() {
    if (licenses.isEmpty()) {
      createTestLicense("TEST-1234-5678-9012", "STANDARD", "test@example.com", "Test User");
      createTestLicense("TEST-PREMIUM-001", "PREMIUM", "premium@example.com", "Premium User");
      createTestLicense("DEV-LICENSE-001", "DEVELOPER", "dev@example.com", "Developer");

      saveLicenses();
      log.info("Default test licenses created");
    }
  }

  private void createTestLicense(String key, String type, String email, String name) {
    License license = new License();
    license.setId(String.valueOf(licenseIdCounter.getAndIncrement()));
    license.setLicenseKey(key);
    license.setLicenseType(type);
    license.setCustomerEmail(email);
    license.setCustomerName(name);
    license.setMaxActivations(5);
    license.setActive(true);
    license.setCreatedAt(Date.from(Instant.now()));
    license.setUpdatedAt(Date.from(Instant.now()));
    license.setFeatures(Arrays.asList("BASIC_PROTECTION", "HEARTBEAT_VERIFICATION"));

    licenses.put(key, license);
  }

  public License findLicenseByKey(String licenseKey) {
    return licenses.get(licenseKey);
  }

  public List<License> findAllLicenses() {
    return new ArrayList<>(licenses.values());
  }

  public void saveLicense(License license) {
    if (license.getId() == null) {
      license.setId(String.valueOf(licenseIdCounter.getAndIncrement()));
    }
    license.setUpdatedAt(Date.from(Instant.now()));
    licenses.put(license.getLicenseKey(), license);
    saveLicenses();
  }

  public void deleteLicense(String licenseKey) {
    licenses.remove(licenseKey);
    activations.remove(licenseKey);
    saveLicenses();
    saveActivations();
  }

  public List<Activation> findActivationsByLicenseKey(String licenseKey) {
    return activations.getOrDefault(licenseKey, new ArrayList<>());
  }

  public void saveActivation(Activation activation) {
    if (activation.getId() == null) {
      activation.setId(String.valueOf(activationIdCounter.getAndIncrement()));
    }
    activation.setUpdatedAt(Date.from(Instant.now()));

    List<Activation> licenseActivations =
        activations.computeIfAbsent(activation.getLicenseKey(), k -> Collections.synchronizedList(new ArrayList<>()));
    synchronized (licenseActivations) {
      licenseActivations.removeIf(a -> a == activation
          || (activation.getHardwareFingerprint() != null
              && activation.getHardwareFingerprint().equals(a.getHardwareFingerprint())));
      licenseActivations.add(activation);
    }
    saveActivations();
  }

  public void removeActivation(String licenseKey, String hardwareFingerprint) {
    List<Activation> licenseActivations = activations.get(licenseKey);
    if (licenseActivations != null) {
      licenseActivations.removeIf(a -> a.getHardwareFingerprint().equals(hardwareFingerprint));
      saveActivations();
    }
  }

  public Session findSessionByToken(String token) {
    return sessions.get(token);
  }

  public void saveSession(Session session) {
    sessions.put(session.getSessionToken(), session);
    saveSessions();
  }

  public void removeSession(String token) {
    sessions.remove(token);
    saveSessions();
  }

  public void saveAuditLog(AuditLog auditLog) {
    if (auditLog.getId() == null) {
      auditLog.setId(String.valueOf(auditLogIdCounter.getAndIncrement()));
    }
    auditLogs.add(auditLog);
    saveAuditLogs();
  }

  public List<AuditLog> findAuditLogs(int limit) {
    return auditLogs.stream()
        .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp()))
        .limit(limit)
        .collect(Collectors.toList());
  }

  private void saveLicenses() {
    saveToFile(LICENSES_FILE, licenses);
  }

  private void saveActivations() {
    saveToFile(ACTIVATIONS_FILE, activations);
  }

  private void saveSessions() {
    saveToFile(SESSIONS_FILE, sessions);
  }

  private void saveAuditLogs() {
    saveToFile(AUDIT_LOGS_FILE, auditLogs);
  }

  private void saveCounters() {
    Map<String, Long> counters = Map.of(
        "licenseId", licenseIdCounter.get(),
        "pluginId", pluginIdCounter.get(),
        "activationId", activationIdCounter.get(),
        "auditLogId", auditLogIdCounter.get()
    );
    saveToFile(COUNTERS_FILE, counters);
  }

  private void saveToFile(String filename, Object data) {
    Path file = dataDirectory.resolve(filename);
    try {
      String json = gson.toJson(data);
      Files.writeString(file, json);
    } catch (IOException e) {
      log.error("Error saving file {}", filename, e);
    }
  }

  @Override
  public boolean isHealthy() {
    try {
      return Files.exists(dataDirectory) && Files.isWritable(dataDirectory);
    } catch (Exception e) {
      log.error("Health check failed", e);
      return false;
    }
  }

  @Override
  public void shutdown() {
    log.info("Cerrando base de datos local...");
    saveCounters();
    log.info("Base de datos local cerrada");
  }

  public Plugin findPluginById(String pluginId) {
    return plugins.get(pluginId);
  }

  public List<Plugin> findAllPlugins() {
    return new ArrayList<>(plugins.values());
  }

  public void savePlugin(Plugin plugin) {
    if (plugin.getId() == null) {
      plugin.setId(String.valueOf(pluginIdCounter.getAndIncrement()));
    }
    plugin.setUpdatedAt(Date.from(Instant.now()));
    plugins.put(plugin.getPluginId(), plugin);
    savePlugins();
  }

  public void deletePlugin(String pluginId) {
    plugins.remove(pluginId);
    savePlugins();
  }

  private void savePlugins() {
    saveToFile(PLUGINS_FILE, plugins);
  }

  public Map<String, Object> getStatistics() {
    Map<String, Object> stats = new HashMap<>();
    stats.put("totalLicenses", licenses.size());
    stats.put("activeLicenses", licenses.values().stream().mapToLong(l -> l.isActive() ? 1 : 0).sum());
    stats.put("totalPlugins", plugins.size());
    stats.put("activePlugins", plugins.values().stream().mapToLong(p -> p.isActive() ? 1 : 0).sum());
    stats.put("totalActivations", activations.values().stream().mapToLong(List::size).sum());
    stats.put("totalSessions", sessions.size());
    stats.put("totalAuditLogs", auditLogs.size());
    stats.put("totalUsers", users.size());
    stats.put("activeUsers", users.values().stream().mapToLong(u -> u.isActive() ? 1 : 0).sum());
    stats.put("totalUserSessions", userSessions.size());
    return stats;
  }

  @Override
  public void saveUser(User user) {
    if (user.getId() == null) {
      user.setId(UUID.randomUUID().toString());
    }
    if (user.getCreatedAt() == null) {
      user.setCreatedAt(Date.from(Instant.now()));
    }
    user.setUpdatedAt(Date.from(Instant.now()));

    users.put(user.getId(), user);
    saveUsers();
    log.debug("User saved: {}", user.getEmail());
  }

  @Override
  public User findUserById(String userId) {
    return users.get(userId);
  }

  @Override
  public User findUserByEmail(String email) {
    return users.values().stream()
        .filter(user -> email.equals(user.getEmail()))
        .findFirst()
        .orElse(null);
  }

  @Override
  public User findUserByUsername(String username) {
    return users.values().stream()
        .filter(user -> username.equals(user.getUsername()))
        .findFirst()
        .orElse(null);
  }

  @Override
  public User findUserByEmailVerificationToken(String token) {
    return users.values().stream()
        .filter(user -> token.equals(user.getEmailVerificationToken()))
        .findFirst()
        .orElse(null);
  }

  @Override
  public User findUserByPasswordResetToken(String token) {
    return users.values().stream()
        .filter(user -> token.equals(user.getPasswordResetToken()))
        .findFirst()
        .orElse(null);
  }

  @Override
  public List<User> findAllUsers() {
    return new ArrayList<>(users.values());
  }

  @Override
  public void deleteUser(String userId) {
    users.remove(userId);

    deleteUserSessionsByUserId(userId);
    saveUsers();
    log.debug("User deleted: {}", userId);
  }

  @Override
  public void saveUserSession(UserSession session) {
    if (session.getSessionId() == null) {
      session.setSessionId(UUID.randomUUID().toString());
    }
    if (session.getCreatedAt() == null) {
      session.setCreatedAt(Date.from(Instant.now()));
    }
    session.setLastAccessAt(Date.from(Instant.now()));

    userSessions.put(session.getSessionId(), session);
    saveUserSessions();
    log.debug("User session saved: {}", session.getSessionId());
  }

  @Override
  public UserSession findUserSessionByToken(String token) {
    return userSessions.values().stream()
        .filter(session -> token.equals(session.getToken()))
        .findFirst()
        .orElse(null);
  }

  @Override
  public UserSession findUserSessionById(String sessionId) {
    return userSessions.get(sessionId);
  }

  @Override
  public List<UserSession> findUserSessionsByUserId(String userId) {
    return userSessions.values().stream()
        .filter(session -> userId.equals(session.getUserId()))
        .collect(Collectors.toList());
  }

  @Override
  public void deleteUserSession(String sessionId) {
    userSessions.remove(sessionId);
    saveUserSessions();
    log.debug("User session deleted: {}", sessionId);
  }

  @Override
  public void deleteUserSessionsByUserId(String userId) {
    List<String> sessionsToRemove = userSessions.values().stream()
        .filter(session -> userId.equals(session.getUserId()))
        .map(UserSession::getSessionId)
        .collect(Collectors.toList());

    sessionsToRemove.forEach(userSessions::remove);
    if (!sessionsToRemove.isEmpty()) {
      saveUserSessions();
      log.debug("Removed {} sessions for user: {}", sessionsToRemove.size(), userId);
    }
  }

  @Override
  public void cleanupExpiredUserSessions() {
    Date now = Date.from(Instant.now());
    List<String> expiredSessions = userSessions.values().stream()
        .filter(session -> session.getExpiresAt() != null && session.getExpiresAt().before(now))
        .map(UserSession::getSessionId)
        .collect(Collectors.toList());

    expiredSessions.forEach(userSessions::remove);
    if (!expiredSessions.isEmpty()) {
      saveUserSessions();
      log.info("Cleaned up {} expired user sessions", expiredSessions.size());
    }
  }

  private void saveUsers() {
    saveToFile(USERS_FILE, users);
  }

  private void saveUserSessions() {
    saveToFile(USER_SESSIONS_FILE, userSessions);
  }
}
