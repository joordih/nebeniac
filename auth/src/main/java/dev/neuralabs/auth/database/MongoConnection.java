package dev.neuralabs.auth.database;

import com.mongodb.MongoClientSettings;
import com.mongodb.MongoCredential;
import com.mongodb.ServerAddress;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.ReplaceOptions;
import dev.neuralabs.auth.config.DatabaseConfig;
import dev.neuralabs.auth.model.*;
import lombok.extern.slf4j.Slf4j;
import org.bson.Document;
import org.bson.UuidRepresentation;
import org.bson.codecs.configuration.CodecRegistry;
import org.bson.codecs.pojo.PojoCodecProvider;
import org.bson.types.ObjectId;
import org.mongojack.JacksonMongoCollection;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import static com.mongodb.client.model.Filters.*;
import static org.bson.codecs.configuration.CodecRegistries.*;

@Slf4j
public class MongoConnection implements DatabaseInterface {
  private MongoClient mongoClient;
  private MongoDatabase database;
  private JacksonMongoCollection<License> licensesCollection;
  private JacksonMongoCollection<Plugin> pluginsCollection;
  private JacksonMongoCollection<Activation> activationsCollection;
  private JacksonMongoCollection<Session> sessionsCollection;
  private JacksonMongoCollection<AuditLog> auditLogsCollection;
  private JacksonMongoCollection<User> usersCollection;
  private JacksonMongoCollection<UserSession> userSessionsCollection;

  private final AtomicLong licenseIdCounter = new AtomicLong(1);
  private final AtomicLong pluginIdCounter = new AtomicLong(1);
  private final AtomicLong activationIdCounter = new AtomicLong(1);
  private final AtomicLong auditLogIdCounter = new AtomicLong(1);

  private static MongoConnection instance;

  private MongoConnection() {
  }

  public static synchronized MongoConnection getInstance() {
    if (instance == null) {
      instance = new MongoConnection();
    }
    return instance;
  }

  @Override
  public void initialize() {
    DatabaseConfig config = DatabaseConfig.getInstance();

    try {
      log.info("Connecting to MongoDB at: {}", config.getMongoConnectionString());

      MongoClientSettings.Builder settingsBuilder = MongoClientSettings.builder();

      if (config.getMongoConnectionString().startsWith("mongodb://") ||
          config.getMongoConnectionString().startsWith("mongodb+srv://")) {
        mongoClient = MongoClients.create(config.getMongoConnectionString());
      } else {
        settingsBuilder.applyToClusterSettings(
            builder -> builder.hosts(List.of(new ServerAddress("localhost", 27017))));

        if (config.getMongoUsername() != null && config.getMongoPassword() != null) {
          MongoCredential credential = MongoCredential.createCredential(
              config.getMongoUsername(),
              config.getMongoDatabaseName(),
              config.getMongoPassword().toCharArray());
          settingsBuilder.credential(credential);
        }

        mongoClient = MongoClients.create(settingsBuilder.build());
      }

      CodecRegistry pojoCodecRegistry = fromRegistries(
          MongoClientSettings.getDefaultCodecRegistry(),
          fromProviders(PojoCodecProvider.builder().automatic(true).build()));

      database = mongoClient.getDatabase(config.getMongoDatabaseName())
          .withCodecRegistry(pojoCodecRegistry);

      licensesCollection = JacksonMongoCollection.builder()
          .build(database, "licenses", License.class, UuidRepresentation.STANDARD);
      pluginsCollection = JacksonMongoCollection.builder()
          .build(database, "plugins", Plugin.class, UuidRepresentation.STANDARD);
      activationsCollection = JacksonMongoCollection.builder()
          .build(database, "activations", Activation.class, UuidRepresentation.STANDARD);
      sessionsCollection = JacksonMongoCollection.builder()
          .build(database, "sessions", Session.class, UuidRepresentation.STANDARD);
      auditLogsCollection = JacksonMongoCollection.builder()
          .build(database, "auditLogs", AuditLog.class, UuidRepresentation.STANDARD);
      usersCollection = JacksonMongoCollection.builder()
          .build(database, "users", User.class, UuidRepresentation.STANDARD);
      userSessionsCollection = JacksonMongoCollection.builder()
          .build(database, "userSessions", UserSession.class, UuidRepresentation.STANDARD);

      createIndexes();

      initializeCounters();

      createDefaultLicenses();

      log.info("MongoDB database initialized successfully");
    } catch (Exception e) {
      log.error("Failed to initialize MongoDB connection", e);
      throw new RuntimeException("Could not connect to MongoDB", e);
    }
  }

  private void createIndexes() {
    try {
      licensesCollection.createIndex(new Document("licenseKey", 1));
      pluginsCollection.createIndex(new Document("pluginId", 1));
      activationsCollection.createIndex(new Document("licenseKey", 1));
      sessionsCollection.createIndex(new Document("sessionToken", 1));
      auditLogsCollection.createIndex(new Document("timestamp", -1));
      usersCollection.createIndex(new Document("email", 1));
      usersCollection.createIndex(new Document("emailVerificationToken", 1));
      usersCollection.createIndex(new Document("passwordResetToken", 1));
      userSessionsCollection.createIndex(new Document("token", 1));
      userSessionsCollection.createIndex(new Document("userId", 1));

      log.info("Database indexes created successfully");
    } catch (Exception e) {
      log.warn("Could not create indexes", e);
    }
  }

  private void initializeCounters() {
    try {
      long maxLicenseId = licensesCollection.countDocuments() + 1;
      long maxPluginId = pluginsCollection.countDocuments() + 1;
      long maxActivationId = activationsCollection.countDocuments() + 1;
      long maxAuditLogId = auditLogsCollection.countDocuments() + 1;

      licenseIdCounter.set(maxLicenseId);
      pluginIdCounter.set(maxPluginId);
      activationIdCounter.set(maxActivationId);
      auditLogIdCounter.set(maxAuditLogId);

      log.info("Counters initialized - Licenses: {}, Plugins: {}, Activations: {}, AuditLogs: {}",
          maxLicenseId, maxPluginId, maxActivationId, maxAuditLogId);
    } catch (Exception e) {
      log.warn("Could not initialize counters", e);
    }
  }

  private void createDefaultLicenses() {
    if (licensesCollection.countDocuments() == 0) {
      createTestLicense("TEST-1234-5678-9012", "STANDARD", "test@example.com", "Test User");
      createTestLicense("TEST-PREMIUM-001", "PREMIUM", "premium@example.com", "Premium User");
      createTestLicense("DEV-LICENSE-001", "DEVELOPER", "dev@example.com", "Developer");
      log.info("Created default test licenses");
    }
  }

  private void createTestLicense(String key, String type, String email, String name) {
    License license = new License();
    license.setId(new ObjectId().toHexString());
    license.setLicenseKey(key);
    license.setLicenseType(type);
    license.setCustomerEmail(email);
    license.setCustomerName(name);
    license.setMaxActivations(5);
    license.setActive(true);
    license.setCreatedAt(Date.from(Instant.now()));
    license.setUpdatedAt(Date.from(Instant.now()));
    license.setFeatures(Arrays.asList("BASIC_PROTECTION", "HEARTBEAT_VERIFICATION"));

    licensesCollection.insertOne(license);
  }

  @Override
  public License findLicenseByKey(String licenseKey) {
    return licensesCollection.find(eq("licenseKey", licenseKey)).first();
  }

  @Override
  public List<License> findAllLicenses() {
    return licensesCollection.find().into(new ArrayList<>());
  }

  @Override
  public void saveLicense(License license) {
    if (license.getId() == null) {
      license.setId(new ObjectId().toHexString());
      license.setCreatedAt(Date.from(Instant.now()));
    }
    license.setUpdatedAt(Date.from(Instant.now()));

    if (licensesCollection.find(eq("licenseKey", license.getLicenseKey())).first() != null) {
      licensesCollection.replaceOne(eq("licenseKey", license.getLicenseKey()), license);
    } else {
      licensesCollection.insertOne(license);
    }
  }

  @Override
  public void deleteLicense(String licenseKey) {
    licensesCollection.deleteOne(eq("licenseKey", licenseKey));
    activationsCollection.deleteMany(eq("licenseKey", licenseKey));
  }

  @Override
  public Plugin findPluginById(String pluginId) {
    return pluginsCollection.find(eq("pluginId", pluginId)).first();
  }

  @Override
  public List<Plugin> findAllPlugins() {
    return pluginsCollection.find().into(new ArrayList<>());
  }

  @Override
  public void savePlugin(Plugin plugin) {
    if (plugin.getId() == null) {
      plugin.setId(new ObjectId().toHexString());
      plugin.setCreatedAt(Date.from(Instant.now()));
    }
    plugin.setUpdatedAt(Date.from(Instant.now()));

    if (pluginsCollection.find(eq("pluginId", plugin.getPluginId())).first() != null) {
      pluginsCollection.replaceOne(eq("pluginId", plugin.getPluginId()), plugin);
    } else {
      pluginsCollection.insertOne(plugin);
    }
  }

  @Override
  public void deletePlugin(String pluginId) {
    pluginsCollection.deleteOne(eq("pluginId", pluginId));
  }

  @Override
  public List<Activation> findActivationsByLicenseKey(String licenseKey) {
    return activationsCollection.find(eq("licenseKey", licenseKey)).into(new ArrayList<>());
  }

  @Override
  public void saveActivation(Activation activation) {
    var filter = and(
        eq("licenseKey", activation.getLicenseKey()),
        eq("hardwareFingerprint", activation.getHardwareFingerprint()));

    Activation existing = activationsCollection.find(filter).first();

    if (existing != null) {
      activation.setId(existing.getId());

      activation.setActivatedAt(existing.getActivatedAt());
    } else {
      activation.setId(new ObjectId().toHexString());
      activation.setActivatedAt(Date.from(Instant.now()));
    }

    activation.setUpdatedAt(Date.from(Instant.now()));

    activationsCollection.replaceOne(filter, activation, new ReplaceOptions().upsert(true));
  }

  @Override
  public void removeActivation(String licenseKey, String hardwareFingerprint) {
    activationsCollection.deleteOne(and(
        eq("licenseKey", licenseKey),
        eq("hardwareFingerprint", hardwareFingerprint)));
  }

  @Override
  public Session findSessionByToken(String token) {
    return sessionsCollection.find(eq("sessionToken", token)).first();
  }

  @Override
  public void saveSession(Session session) {
    if (sessionsCollection.find(eq("sessionToken", session.getSessionToken())).first() != null) {
      sessionsCollection.replaceOne(eq("sessionToken", session.getSessionToken()), session);
    } else {
      sessionsCollection.insertOne(session);
    }
  }

  @Override
  public void removeSession(String token) {
    sessionsCollection.deleteOne(eq("sessionToken", token));
  }

  @Override
  public void saveAuditLog(AuditLog auditLog) {
    if (auditLog.getId() == null) {
      auditLog.setId(new ObjectId().toHexString());
    }
    auditLogsCollection.insertOne(auditLog);
  }

  @Override
  public List<AuditLog> findAuditLogs(int limit) {
    return auditLogsCollection.find()
        .sort(new Document("timestamp", -1))
        .limit(limit)
        .into(new ArrayList<>());
  }

  @Override
  public Map<String, Object> getStatistics() {
    Map<String, Object> stats = new HashMap<>();

    long totalLicenses = licensesCollection.countDocuments();
    long activeLicenses = licensesCollection.countDocuments(eq("active", true));
    long totalPlugins = pluginsCollection.countDocuments();
    long activePlugins = pluginsCollection.countDocuments(eq("active", true));
    long totalActivations = activationsCollection.countDocuments();
    long totalSessions = sessionsCollection.countDocuments();
    long totalAuditLogs = auditLogsCollection.countDocuments();

    long totalUsers = usersCollection.countDocuments();
    long activeUsers = usersCollection.countDocuments(eq("active", true));
    long totalUserSessions = userSessionsCollection.countDocuments();

    stats.put("totalLicenses", totalLicenses);
    stats.put("activeLicenses", activeLicenses);
    stats.put("totalPlugins", totalPlugins);
    stats.put("activePlugins", activePlugins);
    stats.put("totalActivations", totalActivations);
    stats.put("totalSessions", totalSessions);
    stats.put("totalAuditLogs", totalAuditLogs);
    stats.put("totalUsers", totalUsers);
    stats.put("activeUsers", activeUsers);
    stats.put("totalUserSessions", totalUserSessions);

    return stats;
  }

  @Override
  public boolean isHealthy() {
    try {
      database.runCommand(new Document("ping", 1));
      return true;
    } catch (Exception e) {
      log.error("MongoDB health check failed", e);
      return false;
    }
  }

  @Override
  public void saveUser(User user) {
    if (user.getId() == null) {
      user.setId(new ObjectId().toHexString());
      user.setCreatedAt(Date.from(Instant.now()));
    }
    user.setUpdatedAt(Date.from(Instant.now()));

    if (usersCollection.find(eq("email", user.getEmail())).first() != null) {
      usersCollection.replaceOne(eq("email", user.getEmail()), user);
    } else {
      usersCollection.insertOne(user);
    }
  }

  @Override
  public User findUserById(String userId) {
    if (userId == null || !ObjectId.isValid(userId)) {
      return null;
    }
    return usersCollection.find(eq("_id", new ObjectId(userId))).first();
  }

  @Override
  public User findUserByEmail(String email) {
    return usersCollection.find(regex("email", "^" + Pattern.quote(email) + "$", "i")).first();
  }

  @Override
  public User findUserByUsername(String username) {
    return usersCollection.find(eq("username", username)).first();
  }

  @Override
  public User findUserByEmailVerificationToken(String token) {
    return usersCollection.find(eq("emailVerificationToken", token)).first();
  }

  @Override
  public User findUserByPasswordResetToken(String token) {
    return usersCollection.find(eq("passwordResetToken", token)).first();
  }

  @Override
  public List<User> findAllUsers() {
    return usersCollection.find().into(new ArrayList<>());
  }

  @Override
  public void deleteUser(String userId) {
    if (userId != null && ObjectId.isValid(userId)) {
      usersCollection.deleteOne(eq("_id", new ObjectId(userId)));
    }

    deleteUserSessionsByUserId(userId);
  }

  @Override
  public void saveUserSession(UserSession session) {
    if (session.getSessionId() == null) {
      session.setSessionId(new ObjectId().toHexString());
      session.setCreatedAt(Date.from(Instant.now()));
    }
    session.setLastAccessAt(Date.from(Instant.now()));

    if (userSessionsCollection.find(eq("token", session.getToken())).first() != null) {
      userSessionsCollection.replaceOne(eq("token", session.getToken()), session);
    } else {
      userSessionsCollection.insertOne(session);
    }
  }

  @Override
  public UserSession findUserSessionByToken(String token) {
    return userSessionsCollection.find(eq("token", token)).first();
  }

  @Override
  public UserSession findUserSessionById(String sessionId) {
    return userSessionsCollection.find(eq("sessionId", sessionId)).first();
  }

  @Override
  public List<UserSession> findUserSessionsByUserId(String userId) {
    return userSessionsCollection.find(eq("userId", userId)).into(new ArrayList<>());
  }

  @Override
  public void deleteUserSession(String sessionId) {
    userSessionsCollection.deleteOne(eq("sessionId", sessionId));
  }

  @Override
  public void deleteUserSessionsByUserId(String userId) {
    userSessionsCollection.deleteMany(eq("userId", userId));
  }

  @Override
  public void cleanupExpiredUserSessions() {
    Date now = Date.from(Instant.now());
    userSessionsCollection.deleteMany(lt("expiresAt", now));
  }

  @Override
  public void shutdown() {
    if (mongoClient != null) {
      log.info("Closing MongoDB connection...");
      mongoClient.close();
      log.info("MongoDB connection closed");
    }
  }
}
