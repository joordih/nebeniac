package dev.neuralabs.protector;

import dev.neuralabs.protector.util.AESUtil.EncryptedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

public class JarWriter {
  private static final Logger logger = LoggerFactory.getLogger(JarWriter.class);
  private static final String SIGNATURE_ENTRY = "NEBENIAC.SIG";

  private final Path outputJarPath;
  private final Map<String, EncryptedData> encryptedClassEntries;
  private final Map<String, byte[]> resourceEntries;
  private final Map<String, Object> pluginYmlContent;
  private final String encryptionId;
  private final PrivateKey signingKey;

  public JarWriter(
      Path outputJarPath,
      Map<String, EncryptedData> encryptedClassEntries,
      Map<String, byte[]> resourceEntries,
      Map<String, Object> pluginYmlContent,
      String encryptionId,
      PrivateKey signingKey) {
    this.outputJarPath = outputJarPath;
    this.encryptedClassEntries = encryptedClassEntries;
    this.resourceEntries = resourceEntries;
    this.pluginYmlContent = pluginYmlContent;
    this.encryptionId = encryptionId;
    this.signingKey = signingKey;
  }

  public String writeProtectedJar() throws IOException {
    logger.info("Writing protected JAR to: {}", outputJarPath);

    try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(outputJarPath))) {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");

      writeEncryptedClasses(jos, digest);
      writeResources(jos);
      writeModifiedPluginYml(jos, digest);
      injectDummyPlugin(jos);

      String signatureBase64 = writeSignature(jos, digest);
      logger.info("Protected JAR written successfully.");
      return signatureBase64;
    } catch (GeneralSecurityException e) {
      throw new IOException("Failed to finalize protected JAR", e);
    }
  }

  private void writeEncryptedClasses(JarOutputStream jos, MessageDigest digest) throws IOException {
    List<String> classNames = new ArrayList<>(encryptedClassEntries.keySet());
    Collections.sort(classNames);

    for (String className : classNames) {
      EncryptedData encryptedData = encryptedClassEntries.get(className);
      String encryptedName = className.replace(".class", ".encrypted");
      String ivName = className.replace(".class", ".iv");

      jos.putNextEntry(new ZipEntry(encryptedName));
      byte[] cipherBytes = encryptedData.getEncryptedBytes();
      jos.write(cipherBytes);
      jos.closeEntry();
      updateDigest(digest, encryptedName, cipherBytes);

      jos.putNextEntry(new ZipEntry(ivName));
      byte[] ivBytes = encryptedData.getIv();
      jos.write(ivBytes);
      jos.closeEntry();
      updateDigest(digest, ivName, ivBytes);
    }
  }

  private void writeResources(JarOutputStream jos) throws IOException {
    for (Map.Entry<String, byte[]> entry : resourceEntries.entrySet()) {
      if (!entry.getKey().equals("plugin.yml")) {
        jos.putNextEntry(new ZipEntry(entry.getKey()));
        jos.write(entry.getValue());
        jos.closeEntry();
      }
    }
  }

  private void writeModifiedPluginYml(JarOutputStream jos, MessageDigest digest) throws IOException {
    logger.info("Modificando plugin.yml para usar DummyPlugin.");
    Map<String, Object> modifiedPluginYml = new HashMap<>(pluginYmlContent);
    modifiedPluginYml.put("main", "dev.neuralabs.plugin.DummyPlugin");
    modifiedPluginYml.put("encryption-id", encryptionId);
    modifiedPluginYml.put("encrypted", true);

    DumperOptions options = new DumperOptions();
    options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
    Yaml yaml = new Yaml(options);
    String yamlString = yaml.dump(modifiedPluginYml);

    jos.putNextEntry(new ZipEntry("plugin.yml"));
    byte[] bytes = yamlString.getBytes(StandardCharsets.UTF_8);
    jos.write(bytes);
    jos.closeEntry();
    updateDigest(digest, "plugin.yml", bytes);
  }

  private String writeSignature(JarOutputStream jos, MessageDigest digest)
      throws GeneralSecurityException, IOException {
    if (signingKey == null) {
      logger.warn("Signing key not provided - protected JAR will not be signed");
      return null;
    }

    byte[] jarHash = digest.digest();
    Signature signature = Signature.getInstance("Ed25519");
    signature.initSign(signingKey);
    signature.update(jarHash);
    byte[] signatureBytes = signature.sign();
    String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

    jos.putNextEntry(new ZipEntry(SIGNATURE_ENTRY));
    jos.write(signatureBase64.getBytes(StandardCharsets.UTF_8));
    jos.closeEntry();
    return signatureBase64;
  }

  private void updateDigest(MessageDigest digest, String entryName, byte[] data) {
    digest.update(entryName.getBytes(StandardCharsets.UTF_8));
    digest.update(data);
  }

  private void injectDummyPlugin(JarOutputStream jos) throws IOException {
    logger.info("Inyectando DummyPlugin compilado...");

    try {
      String classPath = "target/classes/dev/neuralabs/plugin/DummyPlugin.class";
      File classFile = new File(classPath);

      if (classFile.exists()) {
        byte[] classBytes = Files.readAllBytes(classFile.toPath());

        jos.putNextEntry(new ZipEntry("dev/neuralabs/plugin/DummyPlugin.class"));
        jos.write(classBytes);
        jos.closeEntry();

        logger.info("DummyPlugin injected successfully");
      } else {
        logger.error("DummyPlugin.class not found at: " + classPath);
        logger.info("Make sure to build the project first with: mvn compile");
      }
    } catch (Exception e) {
      logger.error("Error inyectando DummyPlugin: " + e.getMessage());
    }
  }
}
