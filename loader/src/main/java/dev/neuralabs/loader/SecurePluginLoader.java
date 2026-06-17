package dev.neuralabs.loader;

import dev.neuralabs.loader.crypto.CryptoProvider;
import dev.neuralabs.loader.crypto.CryptoProviderFactory;
import dev.neuralabs.loader.license.HardwareFingerprint;
import dev.neuralabs.loader.manager.SecurePluginManager;
import dev.neuralabs.loader.protection.BackendProtectionInfo;
import dev.neuralabs.loader.protection.JavaAgentDetector;
import dev.neuralabs.loader.protection.JarSignatureVerifier;
import dev.neuralabs.loader.service.BackendService;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;
import org.yaml.snakeyaml.Yaml;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SecurePluginLoader extends JavaPlugin {

  private Logger logger;
  private SecurePluginManager pluginManager;
  private CryptoProvider cryptoProvider;
  private BackendService backendService;
  private HardwareFingerprint hardwareFingerprint;
  private String fingerprintSalt;
  private PublicKey trustedSignatureKey;

  @Override
  public void onEnable() {
    logger = getLogger();
    logger.info("Iniciando SecurePluginLoader...");

    // Registrar BouncyCastle como proveedor de seguridad para Ed25519
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
      logger.info("BouncyCastle provider registered for Ed25519 support");
    }

    saveDefaultConfig();
    
    // Sincronizar valores de seguridad del JAR al config en disco
    syncSecurityValuesFromJar();

    try {
      runAgentDetection();
      initializeSecuritySettings();
      initializeBackendService();
      initializeCryptoProvider();
      initializePluginManager();
      loadSecurePlugins();

      logger.info("SecurePluginLoader started successfully");
    } catch (Exception e) {
      logger.log(Level.SEVERE, "Critical error during initialization", e);
      getServer().getPluginManager().disablePlugin(this);
    }
  }

  @Override
  public void onDisable() {
    logger.info("Disabling SecurePluginLoader...");

    if (pluginManager != null) {
      pluginManager.shutdown();
    }

    logger.info("SecurePluginLoader disabled");
  }

  /**
   * Sincroniza los valores de seguridad del config.yml dentro del JAR 
   * al config.yml en disco, sobrescribiendo valores antiguos
   */
  @SuppressWarnings("unchecked")
  private void syncSecurityValuesFromJar() {
    try {
      // Obtener el path del JAR del plugin
      File jarFile = getFile();
      
      logger.info("Syncing security values from JAR to disk config...");
      
      // Leer config.yml del JAR
      try (JarFile jar = new JarFile(jarFile)) {
        JarEntry configEntry = jar.getJarEntry("config.yml");
        if (configEntry == null) {
          logger.warning("config.yml not found in JAR, skipping security sync");
          return;
        }
        
        // Cargar config del JAR
        Yaml yaml = new Yaml();
        Object loadedData;
        try (InputStream is = jar.getInputStream(configEntry)) {
          loadedData = yaml.load(is);
        }
        
        if (!(loadedData instanceof Map)) {
          logger.warning("Invalid config.yml format in JAR");
          return;
        }
        
        Map<String, Object> jarConfig = (Map<String, Object>) loadedData;
        
        // Extraer valores de seguridad del JAR
        Map<String, Object> jarSecurity = getNestedMap(jarConfig, "security");
        if (jarSecurity == null) {
          logger.fine("No security section found in JAR config");
          return;
        }
        
        String jarSignatureKey = (String) jarSecurity.get("signature-public-key");
        String jarFingerprintSalt = (String) jarSecurity.get("hardware-fingerprint-salt");
        
        boolean updated = false;
        
        // SIEMPRE actualizar signature-public-key si existe en el JAR (sobrescribir el valor anterior)
        if (jarSignatureKey != null && !jarSignatureKey.isBlank()) {
          String currentKey = getConfig().getString("security.signature-public-key");
          logger.info("FORCE updating security.signature-public-key from JAR");
          getConfig().set("security.signature-public-key", jarSignatureKey);
          logger.info("  Previous: " + (currentKey != null ? currentKey.substring(0, Math.min(20, currentKey.length())) + "..." : "null"));
          logger.info("  Updated to: " + jarSignatureKey.substring(0, Math.min(20, jarSignatureKey.length())) + "...");
          updated = true;
        }
        
        // SIEMPRE actualizar hardware-fingerprint-salt si existe en el JAR (sobrescribir el valor anterior)
        if (jarFingerprintSalt != null && !jarFingerprintSalt.isBlank()) {
          String currentSalt = getConfig().getString("security.hardware-fingerprint-salt");
          logger.info("FORCE updating security.hardware-fingerprint-salt from JAR");
          getConfig().set("security.hardware-fingerprint-salt", jarFingerprintSalt);
          logger.info("  Previous: " + (currentSalt != null ? currentSalt.substring(0, Math.min(16, currentSalt.length())) + "..." : "null"));
          logger.info("  Updated to: " + jarFingerprintSalt.substring(0, Math.min(16, jarFingerprintSalt.length())) + "...");
          updated = true;
        }
        
        // Save ONLY the security changes (all other config values are preserved)
        if (updated) {
          saveConfig();
          logger.info("Security values synchronized from JAR (all other config values preserved)");
          logger.info("Only updated: security.signature-public-key and security.hardware-fingerprint-salt");
        } else {
          logger.fine("Security values already up to date");
        }
        
      }
    } catch (Exception e) {
      logger.log(Level.WARNING, "Error syncing security values from JAR", e);
    }
  }
  
  /**
   * Helper para obtener un mapa anidado del config
   */
  @SuppressWarnings("unchecked")
  private Map<String, Object> getNestedMap(Map<String, Object> config, String key) {
    Object value = config.get(key);
    if (value instanceof Map) {
      return (Map<String, Object>) value;
    }
    return null;
  }

  private void runAgentDetection() throws Exception {
    JavaAgentDetector detector = new JavaAgentDetector(logger);
    JavaAgentDetector.DetectionResult result = detector.detect();
    if (result.isDetected()) {
      logger.severe("Java agent detected: " + result.getDetails());
      throw new IllegalStateException("Java agent detected in runtime environment");
    }
  }

  private void initializeSecuritySettings() throws Exception {
    fingerprintSalt = getConfig().getString("security.hardware-fingerprint-salt");
    if (fingerprintSalt == null || fingerprintSalt.isBlank()) {
      throw new IllegalStateException("Missing security.hardware-fingerprint-salt in configuration");
    }
    hardwareFingerprint = new HardwareFingerprint(logger);

    String publicKeyBase64 = getConfig().getString("security.signature-public-key");
    if (publicKeyBase64 == null || publicKeyBase64.isBlank()) {
      throw new IllegalStateException("Missing security.signature-public-key in configuration");
    }
    trustedSignatureKey = loadTrustedPublicKey(publicKeyBase64.trim());

    logger.info("Security settings loaded (fingerprint salt length: " + fingerprintSalt.length() + " )");
  }

  private PublicKey loadTrustedPublicKey(String publicKeyBase64) throws Exception {
    logger.info("Attempting to load public key (length: " + publicKeyBase64.length() + ")");

    // Detect Base64URL (contains - or _) vs standard Base64
    boolean isBase64Url = publicKeyBase64.contains("-") || publicKeyBase64.contains("_");

    byte[] keyBytes;
    if (isBase64Url) {
      logger.fine("Detected Base64URL format, adding padding if needed");
      // Base64URL — add padding if missing
      String paddedKey = addBase64Padding(publicKeyBase64);
      keyBytes = Base64.getUrlDecoder().decode(paddedKey);
    } else {
      logger.fine("Using standard Base64 decoder");
      // Standard Base64
      keyBytes = Base64.getDecoder().decode(publicKeyBase64);
    }
    
    logger.info("Successfully decoded key bytes (length: " + keyBytes.length + ")");
    
    // Intentar primero con Ed25519, luego con EdDSA si falla
    KeyFactory factory;
    try {
      factory = KeyFactory.getInstance("Ed25519", "BC");
      logger.fine("Using Ed25519 KeyFactory from BouncyCastle");
    } catch (NoSuchAlgorithmException e) {
      // Fall back to EdDSA which is more widely supported
      logger.info("Ed25519 not available, trying EdDSA");
      factory = KeyFactory.getInstance("EdDSA", "BC");
    }
    
    return factory.generatePublic(new X509EncodedKeySpec(keyBytes));
  }

  private String addBase64Padding(String base64) {
    // Add '=' padding if needed for Base64
    int mod = base64.length() % 4;
    if (mod == 0) {
      return base64;
    }
    return base64 + "=".repeat(4 - mod);
  }

  private void verifyJarSignature(File pluginFile) throws Exception {
    if (trustedSignatureKey == null) {
      throw new IllegalStateException("Trusted signature key not initialized");
    }

    logger.info("Verifying JAR signature for: " + pluginFile.getName());
    
    try (JarFile jarFile = new JarFile(pluginFile)) {
      JarEntry signatureEntry = jarFile.getJarEntry("NEBENIAC.SIG");
      if (signatureEntry == null) {
        logger.severe("Missing NEBENIAC.SIG in JAR: " + pluginFile.getName());
        throw new SecurityException("Missing NEBENIAC.SIG signature file in JAR: " + pluginFile.getName());
      }

      String signatureBase64;
      try (InputStream is = jarFile.getInputStream(signatureEntry)) {
        signatureBase64 = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
      }

      if (signatureBase64.isEmpty()) {
        logger.severe("Empty NEBENIAC.SIG in JAR: " + pluginFile.getName());
        throw new SecurityException("Empty signature for protected JAR: " + pluginFile.getName());
      }

      logger.fine("Signature length: " + signatureBase64.length() + " chars");
      logger.fine("Signature (preview): " + signatureBase64.substring(0, Math.min(32, signatureBase64.length())) + "...");

      boolean valid = JarSignatureVerifier.verify(pluginFile, signatureBase64, trustedSignatureKey, logger);
      if (!valid) {
        logger.severe("Signature verification FAILED for: " + pluginFile.getName());
        logger.severe("Public key algorithm: " + trustedSignatureKey.getAlgorithm());
        logger.severe("Public key format: " + trustedSignatureKey.getFormat());
        throw new SecurityException("Invalid digital signature for protected JAR: " + pluginFile.getName());
      }
      
      logger.info("Signature verification SUCCESS for: " + pluginFile.getName());
    }
  }

  private BackendService.ServerInfo buildServerInfo() {
    int port = getServer().getPort();
    String version = getServer().getVersion();
    String software = getServer().getName();
    BackendService.ServerInfo info = new BackendService.ServerInfo();
    info.setServerName(getServer().getServerName());
    info.setServerPort(port);
    info.setMinecraftVersion(version);
    info.setServerSoftware(software);
    return info;
  }

  private void initializeBackendService() {
    logger.info("Initializing backend service...");

    String serverUrl = getServerUrl();
    backendService = new BackendService(serverUrl, logger);

    logger.info("Backend service initialized: " + serverUrl);
  }

  private void initializeCryptoProvider() throws Exception {
    logger.info("Initializing crypto provider...");

    CryptoProviderFactory factory = CryptoProviderFactory.getInstance(logger);
    String cryptoType = getConfig().getString("crypto.type", "AES");
    cryptoProvider = factory.createProvider(cryptoType);

    logger.info("Crypto provider initialized: " + cryptoProvider.getAlgorithmName());
  }

  private void initializePluginManager() {
    logger.info("Initializing secure plugin manager...");

    pluginManager = new SecurePluginManager(
        cryptoProvider,
        getConfig().getString("license.key"),
        logger,
        this);

    logger.info("Secure plugin manager initialized");
  }

  private void loadSecurePlugins() {
    logger.info("Scanning for protected plugins...");

    File pluginsFolder = getDataFolder().getParentFile();
    File[] pluginFiles = pluginsFolder.listFiles((dir, name) -> name.endsWith(".jar"));

    if (pluginFiles == null || pluginFiles.length == 0) {
      logger.warning("No JAR files found in the plugins folder");
      return;
    }

    int protectedPluginsFound = 0;
    for (File pluginFile : pluginFiles) {
      if (isProtectedPluginFile(pluginFile)) {
        protectedPluginsFound++;
        logger.info("Protected plugin detected: " + pluginFile.getName());

        new BukkitRunnable() {
          @Override
          public void run() {
            try {
              loadProtectedPlugin(pluginFile);
            } catch (Exception e) {
              logger.log(Level.SEVERE, "Error loading protected plugin '" + pluginFile.getName() + "'", e);
            }
          }
        }.runTask(this);
      }
    }

    if (protectedPluginsFound == 0) {
      logger.info("No protected plugins found");
    } else {
      logger.info("Found " + protectedPluginsFound + " protected plugin(s)");
    }
  }

  public String getServerUrl() {
    return getConfig().getString("server-url", "http://localhost:8080");
  }

  public String getLicenseKey() {
    return getConfig().getString("license.key");
  }


  private String generateHardwareFingerprint() {
    if (hardwareFingerprint == null) {
      hardwareFingerprint = new HardwareFingerprint(logger);
    }

    try {
      return hardwareFingerprint.generate(fingerprintSalt);
    } catch (Exception e) {
      logger.warning("Error generating hardware fingerprint: " + e.getMessage());
      return "fallback-" + System.currentTimeMillis();
    }
  }

  private boolean isProtectedPluginFile(File pluginFile) {
    try {
      JarFile jarFile = new JarFile(pluginFile);
      var pluginYmlEntry = jarFile.getEntry("plugin.yml");
      if (pluginYmlEntry != null) {
        try (InputStream is = jarFile.getInputStream(pluginYmlEntry)) {
          Yaml yaml = new Yaml();
          Object loadedData = yaml.load(is);
          if (loadedData instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<String, Object> pluginData = (Map<String, Object>) loadedData;
            String mainClass = (String) pluginData.get("main");

            jarFile.close();
            return "dev.neuralabs.plugin.DummyPlugin".equals(mainClass);
          }
        }
      }

      jarFile.close();
      return false;
    } catch (Exception e) {
      logger.fine("Error checking if " + pluginFile.getName() + " is a protected plugin: " + e.getMessage());
      return false;
    }
  }

  private void loadProtectedPlugin(File pluginFile) throws Exception {
    logger.info("Loading protected plugin: " + pluginFile.getName());

    verifyJarSignature(pluginFile);

    String hardwareFingerprintValue = generateHardwareFingerprint();
    BackendService.ServerInfo serverInfo = buildServerInfo();

    BackendService.LicenseVerificationResult verificationResult = backendService.verifyLicense(
        getLicenseKey(),
        hardwareFingerprintValue,
        serverInfo);

    if (!verificationResult.isSuccess()) {
      throw new SecurityException("Invalid license for protected plugin: " + pluginFile.getName()
          + (verificationResult.getError() != null ? " (" + verificationResult.getError() + ")" : ""));
    }

    String sessionToken = verificationResult.getSessionToken();
    if (sessionToken == null || sessionToken.isBlank()) {
      throw new IllegalStateException("Backend did not return a valid sessionToken after license verification");
    }

    BackendProtectionInfo protectionInfo = new BackendProtectionInfo(
        logger,
        backendService,
        getLicenseKey(),
        hardwareFingerprintValue,
        sessionToken);

    try {
      if (!protectionInfo.isAvailable()) {
        throw new SecurityException(
            "Could not retrieve protection info from backend for: " + pluginFile.getName());
      }

      String originalMainClass = protectionInfo.getOriginalMainClass();
      logger.info("Original main class: " + originalMainClass);

      try (SecurePluginClassLoader classLoader = new SecurePluginClassLoader(
          this,
          getLicenseKey(),
          cryptoProvider,
          pluginFile,
          protectionInfo)) {
        classLoader.loadPlugin(originalMainClass);
      }

      logger.info("Protected plugin loaded successfully: " + pluginFile.getName());
    } finally {
      backendService.clearSessionKey(sessionToken);
    }
  }
}
