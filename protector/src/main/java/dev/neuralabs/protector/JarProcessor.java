package dev.neuralabs.protector;

import dev.neuralabs.protector.util.AESUtil.EncryptedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarProcessor {
  private static final Logger logger = LoggerFactory.getLogger(JarProcessor.class);

  private final Path inputJarPath;
  private String mainClass;
  private final Map<String, byte[]> originalClassEntries = new HashMap<>();
  private final Map<String, EncryptedData> encryptedClassEntries = new HashMap<>();
  private final Map<String, byte[]> resourceEntries = new HashMap<>();
  private Map<String, Object> pluginYmlContent;
  private final EncryptionUtil encryptionUtil;

  private final List<String> targetPackages;

  public JarProcessor(Path inputJarPath) throws NoSuchAlgorithmException {
    this.inputJarPath = inputJarPath;
    this.encryptionUtil = new EncryptionUtil();
    this.targetPackages = List.of("net.kerfu.alcachofa");
  }

  public JarProcessor(Path inputJarPath, List<String> targetPackages) throws NoSuchAlgorithmException {
    this.inputJarPath = inputJarPath;
    this.targetPackages = targetPackages != null && !targetPackages.isEmpty()
        ? targetPackages
        : List.of("net.kerfu.alcachofa");
    this.encryptionUtil = new EncryptionUtil();
  }

  public void loadAndAnalyzeAndEncryptJar() throws Exception {
    logger.info("Loading, analyzing and encrypting JAR: {}", inputJarPath);
    try (JarFile jarFile = new JarFile(inputJarPath.toFile())) {
      jarFile.stream().forEach(entry -> {
        try {
          if (!entry.isDirectory()) {
            byte[] data = readEntry(jarFile, entry);
            if (entry.getName().endsWith(".class")) {
              if (isClassInTargetPackage(entry.getName())) {
                logger.info("Encrypting target-package class: {}", entry.getName());
                EncryptedData encrypted = encryptionUtil.encryptClass(data);
                encryptedClassEntries.put(entry.getName(), encrypted);
                originalClassEntries.put(entry.getName(), data);
              } else {
                resourceEntries.put(entry.getName(), data);
                originalClassEntries.put(entry.getName(), data);
              }
            } else if (entry.getName().equals("plugin.yml")) {
              pluginYmlContent = new Yaml().load(new String(data));
              if (pluginYmlContent.containsKey("main")) {
                mainClass = (String) pluginYmlContent.get("main");
                logger.info("Main class encontrada en plugin.yml: {}", mainClass);
              }
              resourceEntries.put(entry.getName(), data);
            } else {
              resourceEntries.put(entry.getName(), data);
            }
          }
        } catch (Exception e) {
          logger.error("Error processing JAR entry: {}", entry.getName(), e);
        }
      });
    }
    logger.info("JAR procesado. Clases cifradas: {}, Recursos: {}", encryptedClassEntries.size(),
        resourceEntries.size());
  }

  private byte[] readEntry(JarFile jarFile, JarEntry entry) throws IOException {
    try (InputStream is = jarFile.getInputStream(entry)) {
      return is.readAllBytes();
    }
  }

  public String getMainClass() {
    return mainClass;
  }

  public Map<String, EncryptedData> getEncryptedClassEntries() {
    return encryptedClassEntries;
  }

  public Map<String, byte[]> getResourceEntries() {
    return resourceEntries;
  }

  public Map<String, Object> getPluginYmlContent() {
    return pluginYmlContent;
  }

  public EncryptionUtil getEncryptionUtil() {
    return encryptionUtil;
  }

  private boolean isClassInTargetPackage(String classPath) {
    if (targetPackages == null || targetPackages.isEmpty()) {
      return false;
    }

    for (String targetPackage : targetPackages) {
      String targetPackagePath = targetPackage.replace('.', '/') + "/";
      if (classPath.startsWith(targetPackagePath)) {
        return true;
      }
    }
    return false;
  }
}
