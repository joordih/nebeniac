package dev.neuralabs.loader.protection;

import lombok.Getter;

import java.io.File;
import java.io.InputStream;
import java.util.Properties;
import java.util.jar.JarFile;
import java.util.logging.Logger;

@Getter
public class NebeniacProtectionInfo {

  private final Logger logger;
  private final String encryptionKey;
  private final String originalMainClass;
  private final boolean available;

  public NebeniacProtectionInfo(Logger logger, ClassLoader classLoader) {
    this.logger = logger;

    Properties props = loadProtectionProperties(classLoader);
    if (props != null) {
      this.encryptionKey = props.getProperty("encryption.key");
      this.originalMainClass = props.getProperty("original.main.class");
      this.available = encryptionKey != null && originalMainClass != null;

      if (available) {
        logger.info("NebeniacProtectionInfo cargado - Clase original: " + originalMainClass);
      }
    } else {
      this.encryptionKey = null;
      this.originalMainClass = null;
      this.available = false;
    }
  }

  public NebeniacProtectionInfo(Logger logger, File jarFile) {
    this.logger = logger;

    Properties props = loadProtectionProperties(jarFile);
    if (props != null) {
      this.encryptionKey = props.getProperty("encryption.key");
      this.originalMainClass = props.getProperty("original.main.class");
      this.available = encryptionKey != null && originalMainClass != null;

      if (available) {
        logger.info("NebeniacProtectionInfo cargado desde JAR - Clase original: " + originalMainClass);
      }
    } else {
      this.encryptionKey = null;
      this.originalMainClass = null;
      this.available = false;
    }
  }

  private Properties loadProtectionProperties(ClassLoader classLoader) {
    try (InputStream is = classLoader.getResourceAsStream("nebeniac-protection.properties")) {
      if (is != null) {
        Properties props = new Properties();
        props.load(is);
        return props;
      }
    } catch (Exception e) {
      logger.fine("Could not load protection properties: " + e.getMessage());
    }
    return null;
  }

  private Properties loadProtectionProperties(File jarFile) {
    try (JarFile jar = new JarFile(jarFile)) {
      var entry = jar.getEntry("nebeniac-protection.properties");
      if (entry != null) {
        try (InputStream is = jar.getInputStream(entry)) {
          Properties props = new Properties();
          props.load(is);
          return props;
        }
      }
    } catch (Exception e) {
      logger.fine("Could not load protection properties from JAR: " + e.getMessage());
    }
    return null;
  }


  public byte[] getEncryptionKeyBytes() {
    if (encryptionKey != null) {
      try {
        return java.util.Base64.getDecoder().decode(encryptionKey);
      } catch (Exception e) {
        logger.warning("Error decodificando clave de cifrado: " + e.getMessage());
      }
    }
    return null;
  }
}
