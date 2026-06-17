package dev.neuralabs.protector.bootstrap;

import org.bukkit.plugin.java.JavaPlugin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;


public class SecureBootstrap extends JavaPlugin {

  private static final Logger logger = LoggerFactory.getLogger(SecureBootstrap.class);
  private static final String AES_ALGORITHM = "AES";
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int GCM_TAG_LENGTH = 128;

  private final ConcurrentHashMap<String, byte[]> decryptedCache = new ConcurrentHashMap<>();
  private String originalMainClass;
  private String encryptionKeyBase64;

  @Override
  public void onEnable() {
    logger.info("SecureBootstrap started - loading original plugin...");

    try {

      loadProtectionInfo();

      if (originalMainClass == null) {
        logger.error("Original main class not found");
        return;
      }

      logger.info("Original main class: " + originalMainClass);


      SecureClassLoader secureClassLoader = new SecureClassLoader();


      Class<?> originalClass = secureClassLoader.loadClass(originalMainClass);
      JavaPlugin originalPlugin = (JavaPlugin) originalClass.getDeclaredConstructor().newInstance();


      configureOriginalPlugin(originalPlugin);


      originalPlugin.onEnable();

      logger.info("Original plugin loaded successfully");

    } catch (Exception e) {
      logger.error("Error loading original plugin: " + e.getMessage(), e);
    }
  }

  private void loadProtectionInfo() {
    try (InputStream is = getResource("nebeniac-protection.properties")) {
      if (is != null) {
        Properties props = new Properties();
        props.load(is);

        originalMainClass = props.getProperty("original.main.class");
        encryptionKeyBase64 = props.getProperty("encryption.key");

        logger.info("Protection info loaded");
      }
    } catch (Exception e) {
      logger.error("Error loading protection info: " + e.getMessage());
    }
  }

  private void configureOriginalPlugin(JavaPlugin plugin) {
    try {

      setField(plugin, "loader", getPluginLoader());
      setField(plugin, "server", getServer());
      setField(plugin, "file", getFile());
      setField(plugin, "description", getDescription());
      setField(plugin, "dataFolder", getDataFolder());
      setField(plugin, "classLoader", getClass().getClassLoader());

    } catch (Exception e) {
      logger.warn("Error configuring original plugin:" + e.getMessage());
    }
  }

  private void setField(Object instance, String fieldName, Object value) throws Exception {
    Field field = JavaPlugin.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(instance, value);
  }


  private class SecureClassLoader extends ClassLoader {

    public SecureClassLoader() {
      super(SecureBootstrap.class.getClassLoader());
    }

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {

      byte[] cachedBytes = decryptedCache.get(name);
      if (cachedBytes != null) {
        return defineClass(name, cachedBytes, 0, cachedBytes.length);
      }


      try {
        return super.findClass(name);
      } catch (ClassNotFoundException e) {

      }


      if (isPluginClass(name)) {
        byte[] decryptedBytes = decryptClass(name);
        if (decryptedBytes != null) {
          decryptedCache.put(name, decryptedBytes);
          return defineClass(name, decryptedBytes, 0, decryptedBytes.length);
        }
      }

      throw new ClassNotFoundException("Could not load class: " + name);
    }

    private boolean isPluginClass(String className) {

      return className.startsWith("net.kerfu.alcachofa.") ||
          className.startsWith("com.example.") ||
          (!className.startsWith("java.") &&
              !className.startsWith("javax.") &&
              !className.startsWith("org.bukkit.") &&
              !className.startsWith("org.spigotmc.") &&
              !className.startsWith("dev.neuralabs.protector."));
    }

    private byte[] decryptClass(String className) {
      try {
        String classPath = className.replace('.', '/');
        String encryptedPath = classPath + ".encrypted";
        String ivPath = classPath + ".iv";


        byte[] encryptedData;
        try (InputStream is = getResourceAsStream(encryptedPath)) {
          if (is == null) {
            return null;
          }
          encryptedData = is.readAllBytes();
        }


        byte[] iv;
        try (InputStream is = getResourceAsStream(ivPath)) {
          if (is == null) {
            return null;
          }
          iv = is.readAllBytes();
        }


        return decrypt(encryptedData, iv);

      } catch (Exception e) {
        logger.debug("Error descifrando clase " + className + ": " + e.getMessage());
        return null;
      }
    }

    private byte[] decrypt(byte[] encryptedData, byte[] iv) {
      try {
        byte[] keyBytes = Base64.getDecoder().decode(encryptionKeyBase64);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, AES_ALGORITHM);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        return cipher.doFinal(encryptedData);

      } catch (Exception e) {
        logger.error("Error descifrando datos: " + e.getMessage());
        return null;
      }
    }
  }
}
