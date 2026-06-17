package dev.neuralabs.loader;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bukkit.ChatColor;
import org.bukkit.plugin.PluginDescriptionFile;
import org.bukkit.plugin.PluginLogger;
import org.bukkit.plugin.java.JavaPlugin;

import dev.neuralabs.loader.crypto.CryptoProvider;
import dev.neuralabs.loader.crypto.NebeniacCryptoProvider;
import dev.neuralabs.loader.protection.BackendProtectionInfo;
import dev.neuralabs.loader.protection.NebeniacProtectionInfo;

public class SecurePluginClassLoader extends URLClassLoader {
  private final SecurePluginLoader loaderPlugin;
  private final String licenseKey;
  private final CryptoProvider cryptoProvider;
  private final Logger logger;
  private final PluginDescriptionFile description;
  private final File pluginFile;

  // SECURITY: Cache removed to prevent reflection-based extraction of decrypted bytecode
  // private final ConcurrentHashMap<String, byte[]> cache = new ConcurrentHashMap<>();
  private final NebeniacProtectionInfo protectionInfo;
  private final BackendProtectionInfo backendProtectionInfo;

  public SecurePluginClassLoader(SecurePluginLoader loaderPlugin, String licenseKey,
                                 CryptoProvider cryptoProvider, File pluginFile) throws Exception {
    this(loaderPlugin, licenseKey, cryptoProvider, pluginFile, null);
  }

  public SecurePluginClassLoader(SecurePluginLoader loaderPlugin, String licenseKey,
                                 CryptoProvider cryptoProvider, File pluginFile, BackendProtectionInfo backendProtectionInfo)
      throws Exception {
    super(new URL[]{pluginFile.toURI().toURL()}, loaderPlugin.getClass().getClassLoader());
    this.loaderPlugin = loaderPlugin;
    this.licenseKey = licenseKey;
    this.cryptoProvider = cryptoProvider;
    this.logger = loaderPlugin.getLogger();
    this.pluginFile = pluginFile;
    this.backendProtectionInfo = backendProtectionInfo;

    byte[] pluginYmlBytes = findResourceBytes("plugin.yml");
    if (pluginYmlBytes == null) {
      throw new IllegalStateException("Could not fetch plugin.yml from the plugin file. Check file integrity.");
    }

    try (InputStream ymlStream = new ByteArrayInputStream(pluginYmlBytes)) {
      this.description = new PluginDescriptionFile(ymlStream);
    }

    if (backendProtectionInfo != null) {
      this.protectionInfo = null;
    } else {
      this.protectionInfo = new NebeniacProtectionInfo(logger, this);
    }
  }

  @Override
  protected Class<?> findClass(String name) throws ClassNotFoundException {
    String path = name.replace('.', '/').concat(".class");
    byte[] classBytes = findResourceBytes(path);

    if (classBytes != null) {
      try {
        return defineClass(name, classBytes, 0, classBytes.length);
      } finally {
        // SECURITY: Wipe decrypted bytecode from memory immediately after defining class
        java.util.Arrays.fill(classBytes, (byte) 0);
      }
    }

    return super.findClass(name);
  }

  @Override
  public URL findResource(String name) {
    if (name.endsWith(".class")) {
      return super.findResource(name);
    }

    byte[] resourceBytes = findResourceBytes(name);
    if (resourceBytes != null) {
      try {
        final byte[] finalBytes = resourceBytes;

        // Compatible con Java 11 - usar constructor URL antiguo
        return new URL("x-buffer", null, -1, name, new URLStreamHandler() {
          @Override
          protected URLConnection openConnection(URL u) {
            return new URLConnection(u) {
              @Override
              public void connect() {
              }

              @Override
              public InputStream getInputStream() {
                return new ByteArrayInputStream(finalBytes);
              }
            };
          }
        });
      } catch (Exception e) {
        logger.log(Level.FINE, "Error creating URL for resource " + name, e);
      }
    }
    return super.findResource(name);
  }

  private byte[] findResourceBytes(String resourcePath) {
    try {
      logger.fine("Buscando recurso: " + resourcePath);

      if (resourcePath.endsWith(".class")) {
        return loadEncryptedClass(resourcePath);
      } else {
        return loadResource(resourcePath);
      }
    } catch (Exception e) {
      logger.warning("Error loading resource '" + resourcePath + "': " + e.getMessage());
      return null;
    }
  }

  private byte[] loadEncryptedClass(String classPath) {
    try {
      String className = classPath.substring(0, classPath.length() - 6).replace('/', '.');

      if (!isPluginClass(className)) {
        return null;
      }

      if ((backendProtectionInfo != null && backendProtectionInfo.isAvailable()) ||
          (protectionInfo != null && protectionInfo.isAvailable())) {
        byte[] decryptedBytes = loadWithNebeniacFormat(className);
        if (isValidJavaClassFile(decryptedBytes)) {
          logger.fine("Class decrypted using Nebeniac format: " + className);
          return decryptedBytes;
        } else if (decryptedBytes != null) {
          logger.warning("Decrypted bytes are not a valid .class file for: " + className);
        }
      }

      byte[] encryptedBytes = loadEncryptedClassBytes(className);
      if (encryptedBytes == null) {
        return null;
      }

      byte[] decryptedBytes = decryptClassBytes(encryptedBytes, className);
      if (!isValidJavaClassFile(decryptedBytes)) {
        return null;
      }

      logger.fine("Class decrypted successfully: " + className);
      return decryptedBytes;

    } catch (Exception e) {
      logger.fine("Error loading encrypted class " + classPath + ": " + e.getMessage());
      return null;
    }
  }

  private byte[] loadResource(String resourcePath) {
    try {
      if (pluginFile != null) {
        try (JarFile jar = new JarFile(pluginFile)) {
          JarEntry entry = jar.getJarEntry(resourcePath);
          if (entry != null) {
            try (InputStream is = jar.getInputStream(entry)) {
              return is.readAllBytes();
            }
          }
        }
      }
    } catch (Exception e) {
      logger.fine("Error loading resource " + resourcePath + ": " + e.getMessage());
    }
    return null;
  }

  private byte[] loadWithNebeniacFormat(String className) {
    try {
      String encryptedPath = className.replace('.', '/') + ".encrypted";
      String ivPath = className.replace('.', '/') + ".iv";

      byte[] encryptedData = null;
      if (pluginFile != null) {
        try (JarFile jar = new JarFile(pluginFile)) {
          JarEntry entry = jar.getJarEntry(encryptedPath);
          if (entry != null) {
            try (InputStream is = jar.getInputStream(entry)) {
              encryptedData = is.readAllBytes();
            }
          }
        }
      }
      if (encryptedData == null) {
        return null;
      }

      byte[] iv = null;
      if (pluginFile != null) {
        try (JarFile jar = new JarFile(pluginFile)) {
          JarEntry entry = jar.getJarEntry(ivPath);
          if (entry != null) {
            try (InputStream is = jar.getInputStream(entry)) {
              iv = is.readAllBytes();
            }
          }
        }
      }
      if (iv == null) {
        return null;
      }

      String encryptionKey;
      if (backendProtectionInfo != null && backendProtectionInfo.isAvailable()) {
        encryptionKey = backendProtectionInfo.getEncryptionKey();
      } else if (protectionInfo != null && protectionInfo.isAvailable()) {
        encryptionKey = protectionInfo.getEncryptionKey();
      } else {
        logger.warning("No encryptionKey available for class: " + className);
        return null;
      }

      NebeniacCryptoProvider nebeniacProvider = new NebeniacCryptoProvider(encryptionKey, logger);
      return nebeniacProvider.decryptWithNebeniacFormat(encryptedData, iv);

    } catch (Exception e) {
      if (e.getMessage() != null && e.getMessage().contains("Tag mismatch")) {
        String pluginName = pluginFile != null ? pluginFile.getName() : "unknown";
        String pluginId = "unknown";

        if (backendProtectionInfo != null && backendProtectionInfo.getPluginMetadata() != null) {
          pluginId = backendProtectionInfo.getPluginMetadata().getPluginId();
        }

        // SECURITY FIX: Do not shutdown server on tag mismatch - only disable the plugin
        loaderPlugin.getServer().getConsoleSender().sendMessage("");
        loaderPlugin.getServer().getConsoleSender()
            .sendMessage(ChatColor.DARK_RED + "" + ChatColor.BOLD
                + "================================================================");
        loaderPlugin.getServer().getConsoleSender()
            .sendMessage(ChatColor.RED + "" + ChatColor.BOLD + "  NEBENIAC SECURITY ERROR - CRITICAL");
        loaderPlugin.getServer().getConsoleSender()
            .sendMessage(ChatColor.DARK_RED + "" + ChatColor.BOLD
                + "================================================================");
        loaderPlugin.getServer().getConsoleSender().sendMessage("");
        loaderPlugin.getServer().getConsoleSender().sendMessage(
            ChatColor.RED + "  The plugin " + ChatColor.YELLOW + pluginName + ChatColor.RED
                + " is encrypted for");
        loaderPlugin.getServer().getConsoleSender().sendMessage(
            ChatColor.RED + "  a different license and cannot run on this server.");
        loaderPlugin.getServer().getConsoleSender().sendMessage("");
        loaderPlugin.getServer().getConsoleSender()
            .sendMessage(ChatColor.GRAY + "  Plugin ID: " + ChatColor.WHITE + pluginId);
        loaderPlugin.getServer().getConsoleSender()
            .sendMessage(ChatColor.GRAY + "  Class: " + ChatColor.WHITE + className);
        loaderPlugin.getServer().getConsoleSender().sendMessage("");
        loaderPlugin.getServer().getConsoleSender().sendMessage(
            ChatColor.GOLD + "  ⚠ " + ChatColor.YELLOW + "Plugin has been disabled for security reasons.");
        loaderPlugin.getServer().getConsoleSender().sendMessage("");
        loaderPlugin.getServer().getConsoleSender()
            .sendMessage(ChatColor.DARK_RED + "" + ChatColor.BOLD
                + "================================================================");
        loaderPlugin.getServer().getConsoleSender().sendMessage("");

        // Disable plugin instead of shutting down server
        logger.severe("Tag mismatch for class " + className + " in plugin " + pluginId + ", disabling plugin.");
        throw new SecurityException("Invalid decryption for this plugin/license - Plugin ID: " + pluginId);
      }

      logger.log(Level.WARNING, "Exception in loadWithNebeniacFormat for " + className, e);
      return null;
    }
  }

  private byte[] loadEncryptedClassBytes(String className) {
    try {
      String encryptedPath = className.replace('.', '/') + ".encrypted";
      try (InputStream is = getResourceAsStream(encryptedPath)) {
        if (is != null) {
          return is.readAllBytes();
        }
      }
    } catch (Exception e) {
      logger.fine("Error loading encrypted bytes for " + className + ": " + e.getMessage());
    }
    return null;
  }

  private byte[] decryptClassBytes(byte[] encryptedData, String className) {
    try {
      if (encryptedData.length < 4) {
        return null;
      }

      int ivLength = ((encryptedData[0] & 0xFF) << 24) |
          ((encryptedData[1] & 0xFF) << 16) |
          ((encryptedData[2] & 0xFF) << 8) |
          (encryptedData[3] & 0xFF);

      if (ivLength <= 0 || ivLength > 32 || encryptedData.length < 4 + ivLength) {
        return null;
      }

      byte[] iv = new byte[ivLength];
      System.arraycopy(encryptedData, 4, iv, 0, ivLength);

      byte[] encrypted = new byte[encryptedData.length - 4 - ivLength];
      System.arraycopy(encryptedData, 4 + ivLength, encrypted, 0, encrypted.length);

      byte[] key = cryptoProvider.generateKey(licenseKey, className);
      byte[] decryptedBytes = cryptoProvider.decrypt(encrypted, key, iv);

      return decryptedBytes;
    } catch (Exception e) {
      logger.fine("Error descifrando clase " + className + ": " + e.getMessage());
      return null;
    }
  }

  private boolean isPluginClass(String className) {
    if (className.startsWith("java.") ||
        className.startsWith("javax.") ||
        className.startsWith("sun.") ||
        className.startsWith("jdk.") ||
        className.startsWith("org.bukkit.") ||
        className.startsWith("org.spigotmc.") ||
        className.startsWith("net.minecraft.") ||
        className.startsWith("com.mojang.")) {
      return false;
    }

    if (backendProtectionInfo != null && backendProtectionInfo.getTargetPackages() != null) {
      for (String targetPackage : backendProtectionInfo.getTargetPackages()) {
        if (className.startsWith(targetPackage)) {
          return true;
        }
      }
    }

    return className.startsWith("dev.neuralabs.plugin.") ||
        className.startsWith("com.example.") ||
        className.startsWith("net.kerfu.");
  }

  private boolean isValidJavaClassFile(byte[] classBytes) {
    if (classBytes == null || classBytes.length < 4) {
      return false;
    }

    return (classBytes[0] & 0xFF) == 0xCA &&
        (classBytes[1] & 0xFF) == 0xFE &&
        (classBytes[2] & 0xFF) == 0xBA &&
        (classBytes[3] & 0xFF) == 0xBE;
  }

  public void loadPlugin(String mainClassName) throws Exception {
    String actualMainClass = mainClassName;

    if (backendProtectionInfo != null && backendProtectionInfo.isAvailable()) {
      actualMainClass = backendProtectionInfo.getOriginalMainClass();
      logger.info("Usando clase principal original desde Backend: " + actualMainClass);
    } else if (protectionInfo != null && protectionInfo.isAvailable()
        && protectionInfo.getOriginalMainClass() != null) {
      actualMainClass = protectionInfo.getOriginalMainClass();
      logger.info("Usando clase principal original desde NebeniacProtection: " + actualMainClass);
    }

    Class<?> mainClass = Class.forName(actualMainClass, true, this);

    JavaPlugin pluginInstance = createPluginInstance(mainClass);

    injectDependencies(pluginInstance);

    registerPlugin(pluginInstance);

    loaderPlugin.getServer().getPluginManager().enablePlugin(pluginInstance);
  }

  private JavaPlugin createPluginInstance(Class<?> mainClass) throws Exception {
    try {
      Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
      Field theUnsafeField = unsafeClass.getDeclaredField("theUnsafe");
      theUnsafeField.setAccessible(true);
      Object unsafe = theUnsafeField.get(null);

      Method allocateInstance = unsafeClass.getMethod("allocateInstance", Class.class);
      JavaPlugin plugin = (JavaPlugin) allocateInstance.invoke(unsafe, mainClass);

      return plugin;
    } catch (Exception e) {
      JavaPlugin plugin = (JavaPlugin) mainClass.getDeclaredConstructor().newInstance();

      try {
        Field classLoaderField = JavaPlugin.class.getDeclaredField("classLoader");
        classLoaderField.setAccessible(true);
        classLoaderField.set(plugin, this);
      } catch (Exception ex) {
        logger.warning("Could not inject classLoader: " + ex.getMessage());
      }

      return plugin;
    }
  }

  private void registerPlugin(JavaPlugin plugin) throws Exception {
    try {
      Object pluginManager = loaderPlugin.getServer().getPluginManager();
      Field pluginsField = pluginManager.getClass().getDeclaredField("plugins");
      pluginsField.setAccessible(true);
      @SuppressWarnings("unchecked")
      List<Object> plugins = (List<Object>) pluginsField.get(pluginManager);

      plugins.add(plugin);

      Field lookupNamesField = pluginManager.getClass().getDeclaredField("lookupNames");
      lookupNamesField.setAccessible(true);
      @SuppressWarnings("unchecked")
      Map<String, Object> lookupNames = (Map<String, Object>) lookupNamesField.get(pluginManager);

      lookupNames.put(description.getName().toLowerCase(), plugin);

      logger.info("Plugin registered in PluginManager: " + description.getName());

    } catch (Exception e) {
      logger.warning("Could not register plugin in PluginManager: " + e.getMessage());
    }
  }

  private void injectDependencies(JavaPlugin plugin) throws Exception {
    File pluginsRoot = loaderPlugin.getDataFolder().getParentFile();
    File jarFile = pluginFile != null ? pluginFile : new File(pluginsRoot, description.getName());
    File pluginDataFolder = new File(pluginsRoot, description.getName());
    if (!pluginDataFolder.exists()) {
      pluginDataFolder.mkdirs();
    }
    setField(plugin, "loader", loaderPlugin.getPluginLoader());
    setField(plugin, "server", loaderPlugin.getServer());
    setField(plugin, "file", jarFile);
    setField(plugin, "description", this.description);
    setField(plugin, "dataFolder", pluginDataFolder);
    setField(plugin, "classLoader", this);
    Field loggerField = JavaPlugin.class.getDeclaredField("logger");
    loggerField.setAccessible(true);
    if (loggerField.get(plugin) == null) {
      loggerField.set(plugin, new PluginLogger(plugin));
    }
    Field configFileField = JavaPlugin.class.getDeclaredField("configFile");
    configFileField.setAccessible(true);
    if (configFileField.get(plugin) == null) {
      configFileField.set(plugin, new File(pluginDataFolder, "config.yml"));
    }
    plugin.onLoad();
  }

  private void setField(Object instance, String fieldName, Object value) throws Exception {
    Field field = JavaPlugin.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(instance, value);
  }
}
