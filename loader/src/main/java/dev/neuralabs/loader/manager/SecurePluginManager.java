package dev.neuralabs.loader.manager;

import dev.neuralabs.loader.SecurePluginClassLoader;
import dev.neuralabs.loader.SecurePluginLoader;
import dev.neuralabs.loader.crypto.CryptoProvider;
import lombok.Getter;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

@Getter
public class SecurePluginManager {
  private final CryptoProvider cryptoProvider;
  private final String licenseKey;
  private final Logger logger;
  private final SecurePluginLoader loaderPlugin;

  private final ConcurrentHashMap<String, SecurePluginClassLoader> loadedPlugins = new ConcurrentHashMap<>();
  private final List<String> loadedPluginNames = new ArrayList<>();

  public SecurePluginManager(CryptoProvider cryptoProvider, String licenseKey,
                             Logger logger, SecurePluginLoader loaderPlugin) {
    this.cryptoProvider = cryptoProvider;
    this.licenseKey = licenseKey;
    this.logger = logger;
    this.loaderPlugin = loaderPlugin;
  }

  public void loadSecurePlugin(File pluginFile, String mainClass) throws Exception {
    String pluginName = pluginFile.getName();

    if (loadedPlugins.containsKey(pluginName)) {
      logger.warning("Plugin already loaded: " + pluginName);
      return;
    }

    logger.info("Loading secure plugin: " + pluginName);

    try {
      SecurePluginClassLoader classLoader = new SecurePluginClassLoader(
          getLoaderPlugin(),
          licenseKey,
          cryptoProvider,
          pluginFile
      );

      classLoader.loadPlugin(mainClass);

      loadedPlugins.put(pluginName, classLoader);
      loadedPluginNames.add(pluginName);

      logger.info("Secure plugin loaded successfully: " + pluginName);

    } catch (Exception e) {
      logger.log(Level.SEVERE, "Error loading secure plugin '" + pluginName + "'", e);
      throw e;
    }
  }

  public void unloadSecurePlugin(String pluginName) {
    SecurePluginClassLoader classLoader = loadedPlugins.remove(pluginName);
    if (classLoader != null) {
      loadedPluginNames.remove(pluginName);
      logger.info("Plugin seguro descargado: " + pluginName);
    } else {
      logger.warning("Plugin not found for unloading: " + pluginName);
    }
  }

  public void reloadSecurePlugin(String pluginName) throws Exception {
    logger.info("Reloading secure plugin: " + pluginName);

    unloadSecurePlugin(pluginName);

    File pluginFile = new File(getLoaderPlugin().getDataFolder().getParentFile(), pluginName);
    String mainClass = getLoaderPlugin().getConfig().getString("plugins." + pluginName + ".main-class");

    if (mainClass == null) {
      throw new Exception("Clase principal no especificada para plugin: " + pluginName);
    }

    loadSecurePlugin(pluginFile, mainClass);
  }


  public void shutdown() {
    logger.info("Cerrando gestor de plugins seguros...");

    for (String pluginName : new ArrayList<>(loadedPluginNames)) {
      try {
        unloadSecurePlugin(pluginName);
      } catch (Exception e) {
        logger.warning("Error cerrando plugin " + pluginName + ": " + e.getMessage());
      }
    }

    loadedPlugins.clear();
    loadedPluginNames.clear();

    logger.info("Gestor de plugins seguros cerrado");
  }

  public String getStats() {
    return String.format("Plugins cargados: %d, ClassLoaders activos: %d",
        loadedPluginNames.size(), loadedPlugins.size());
  }
}