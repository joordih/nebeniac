package dev.neuralabs.loader;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bukkit.ChatColor;
import org.bukkit.plugin.PluginDescriptionFile;
import org.bukkit.event.server.PluginEnableEvent;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.plugin.java.JavaPluginLoader;

import dev.neuralabs.loader.crypto.NebeniacCryptoProvider;
import dev.neuralabs.loader.protection.BackendProtectionInfo;

public class SecurePluginClassLoader extends URLClassLoader {
  private final SecurePluginLoader loaderPlugin;
  private final Logger logger;
  private final PluginDescriptionFile description;
  private final File pluginFile;

  private final BackendProtectionInfo backendProtectionInfo;

  public SecurePluginClassLoader(SecurePluginLoader loaderPlugin,
                                 File pluginFile, BackendProtectionInfo backendProtectionInfo)
      throws Exception {
    super(new URL[]{pluginFile.toURI().toURL()}, loaderPlugin.getClass().getClassLoader());
    this.loaderPlugin = loaderPlugin;
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
  }

  @Override
  protected Class<?> findClass(String name) throws ClassNotFoundException {
    String path = name.replace('.', '/').concat(".class");
    byte[] classBytes = findResourceBytes(path);
    if (classBytes == null) {
      classBytes = loadResource(path);
    }
    if (classBytes == null) {
      throw new ClassNotFoundException(name);
    }

    try {
      byte[] definable = PluginBootstrap.redirectPluginConstructor(classBytes);
      return defineClass(name, definable, 0, definable.length);
    } finally {
      Arrays.fill(classBytes, (byte) 0);
    }
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

      if (backendProtectionInfo == null || !backendProtectionInfo.isAvailable()) {
        return null;
      }

      byte[] decryptedBytes = loadWithNebeniacFormat(className);
      if (isValidJavaClassFile(decryptedBytes)) {
        logger.fine("Class decrypted using Nebeniac format: " + className);
        return decryptedBytes;
      } else if (decryptedBytes != null) {
        logger.warning("Decrypted bytes are not a valid .class file for: " + className);
      }

      return null;
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

      if (backendProtectionInfo == null || !backendProtectionInfo.isAvailable()) {
        logger.warning("No encryptionKey available for class: " + className);
        return null;
      }
      String encryptionKey = backendProtectionInfo.getEncryptionKey();

      NebeniacCryptoProvider nebeniacProvider = new NebeniacCryptoProvider(encryptionKey, logger);
      return nebeniacProvider.decryptWithNebeniacFormat(encryptedData, iv);
    } catch (Exception e) {
      if (e.getMessage() != null && e.getMessage().contains("Tag mismatch")) {
        String pluginName = pluginFile != null ? pluginFile.getName() : "unknown";
        String pluginId = "unknown";

        if (backendProtectionInfo != null && backendProtectionInfo.getPluginMetadata() != null) {
          pluginId = backendProtectionInfo.getPluginMetadata().getPluginId();
        }

        printLicenseMismatchBanner(pluginName, pluginId, className);

        logger.severe("Tag mismatch for class " + className + " in plugin " + pluginId + ", disabling plugin.");
        throw new SecurityException("Invalid decryption for this plugin/license - Plugin ID: " + pluginId);
      }

      logger.log(Level.WARNING, "Exception in loadWithNebeniacFormat for " + className, e);
      return null;
    }
  }

  private void printLicenseMismatchBanner(String pluginName, String pluginId, String className) {
    String bar = ChatColor.DARK_RED + "" + ChatColor.BOLD
        + "================================================================";
    String[] lines = {
        "",
        bar,
        ChatColor.RED + "" + ChatColor.BOLD + "  NEBENIAC SECURITY ERROR - CRITICAL",
        bar,
        "",
        ChatColor.RED + "  The plugin " + ChatColor.YELLOW + pluginName + ChatColor.RED + " is encrypted for",
        ChatColor.RED + "  a different license and cannot run on this server.",
        "",
        ChatColor.GRAY + "  Plugin ID: " + ChatColor.WHITE + pluginId,
        ChatColor.GRAY + "  Class: " + ChatColor.WHITE + className,
        "",
        ChatColor.GOLD + "  " + ChatColor.YELLOW + "Plugin has been disabled for security reasons.",
        "",
        bar,
        ""
    };
    var console = loaderPlugin.getServer().getConsoleSender();
    for (String line : lines) {
      console.sendMessage(line);
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

  public JavaPlugin loadPlugin(String mainClassName) throws Exception {
    String actualMainClass = mainClassName;

    if (backendProtectionInfo != null && backendProtectionInfo.isAvailable()) {
      actualMainClass = backendProtectionInfo.getOriginalMainClass();
      logger.info("Usando clase principal original desde Backend: " + actualMainClass);
    }

    Class<?> mainClass = Class.forName(actualMainClass, true, this);
    if (!JavaPlugin.class.isAssignableFrom(mainClass)) {
      throw new IllegalStateException("Main class " + actualMainClass + " does not extend JavaPlugin");
    }

    File dataFolder = new File(loaderPlugin.getDataFolder().getParentFile(), description.getName());
    JavaPluginLoader javaPluginLoader = new JavaPluginLoader(loaderPlugin.getServer());
    JavaPlugin plugin = PluginBootstrap.instantiate(
        mainClass.asSubclass(JavaPlugin.class),
        javaPluginLoader,
        description,
        dataFolder,
        pluginFile);

    plugin.onLoad();
    registerPlugin(plugin);
    enablePlugin(plugin);
    return plugin;
  }

  private void enablePlugin(JavaPlugin plugin) {
    if (plugin.isEnabled()) {
      return;
    }

    plugin.getLogger().info("Enabling " + description.getFullName());
    try {
      Method setEnabled = JavaPlugin.class.getDeclaredMethod("setEnabled", boolean.class);
      setEnabled.setAccessible(true);
      setEnabled.invoke(plugin, true);
    } catch (InvocationTargetException e) {
      logger.log(Level.SEVERE, "Error occurred while enabling " + description.getFullName(), e.getCause());
      return;
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Cannot enable " + description.getFullName(), e);
    }

    loaderPlugin.getServer().getPluginManager().callEvent(new PluginEnableEvent(plugin));
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
}
