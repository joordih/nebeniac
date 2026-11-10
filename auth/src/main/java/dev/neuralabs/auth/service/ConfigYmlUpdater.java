package dev.neuralabs.auth.service;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.jar.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class ConfigYmlUpdater {
    private static final String CONFIG_YML_PATH = "config.yml";
    private static final Pattern SIGNATURE_KEY_PATTERN = Pattern.compile(
        "(signature-public-key:\\s*)([^\\n]*)",
        Pattern.MULTILINE
    );
    private static final Pattern SALT_PATTERN = Pattern.compile(
        "(hardware-fingerprint-salt:\\s*)([^\\n]*)",
        Pattern.MULTILINE
    );

    public void updateConfigInJar(Path jarPath, String signaturePublicKey, String hardwareFingerprintSalt)
            throws Exception {
        log.info("Updating config.yml in JAR: {}", jarPath);

        if (!Files.exists(jarPath)) {
            throw new FileNotFoundException("JAR file not found: " + jarPath);
        }

        Path tempJarPath = Files.createTempFile("config-updated-", ".jar");

        try {
            boolean configFound = false;

            try (JarInputStream jis = new JarInputStream(new FileInputStream(jarPath.toFile()));
                 JarOutputStream jos = new JarOutputStream(new FileOutputStream(tempJarPath.toFile()))) {
                Manifest manifest = jis.getManifest();
                if (manifest != null) {
                    jos.putNextEntry(new JarEntry(JarFile.MANIFEST_NAME));
                    manifest.write(jos);
                    jos.closeEntry();
                }

                JarEntry entry;
                byte[] buffer = new byte[8192];

                while ((entry = jis.getNextJarEntry()) != null) {
                    String entryName = entry.getName();

                    if (entryName.equals(JarFile.MANIFEST_NAME)) {
                        continue;
                    }

                    if (entryName.equals(CONFIG_YML_PATH)) {
                        configFound = true;
                        String originalConfig = readEntryAsString(jis);
                        String updatedConfig = updateConfigContent(
                            originalConfig,
                            signaturePublicKey,
                            hardwareFingerprintSalt
                        );

                        JarEntry newEntry = new JarEntry(CONFIG_YML_PATH);
                        jos.putNextEntry(newEntry);
                        jos.write(updatedConfig.getBytes());
                        jos.closeEntry();

                        log.info("Updated config.yml with signature key and salt");
                    } else {
                        jos.putNextEntry(new JarEntry(entryName));

                        int bytesRead;
                        while ((bytesRead = jis.read(buffer)) != -1) {
                            jos.write(buffer, 0, bytesRead);
                        }

                        jos.closeEntry();
                    }
                }
            }

            if (!configFound) {
                log.warn("config.yml not found in JAR, creating new one");

                addNewConfigToJar(tempJarPath, signaturePublicKey, hardwareFingerprintSalt);
            }

            Files.move(tempJarPath, jarPath, StandardCopyOption.REPLACE_EXISTING);
            log.info("Successfully updated config.yml in JAR");
        } catch (Exception e) {
            Files.deleteIfExists(tempJarPath);
            throw e;
        }
    }

    private String readEntryAsString(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int bytesRead;

        while ((bytesRead = is.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }

        return baos.toString("UTF-8");
    }

    private String updateConfigContent(String originalConfig, String signatureKey, String salt) {
        String updated = originalConfig;

        Matcher signatureMatcher = SIGNATURE_KEY_PATTERN.matcher(updated);
        if (signatureMatcher.find()) {
            updated = signatureMatcher.replaceFirst("$1\"" + signatureKey + "\"");
            log.debug("Replaced existing signature-public-key");
        } else {
            updated = addSignatureKeyToConfig(updated, signatureKey);
            log.debug("Added new signature-public-key");
        }

        Matcher saltMatcher = SALT_PATTERN.matcher(updated);
        if (saltMatcher.find()) {
            updated = saltMatcher.replaceFirst("$1\"" + salt + "\"");
            log.debug("Replaced existing hardware-fingerprint-salt");
        } else {
            updated = addSaltToConfig(updated, salt);
            log.debug("Added new hardware-fingerprint-salt");
        }

        return updated;
    }

    private String addSignatureKeyToConfig(String config, String signatureKey) {
        Pattern securityPattern = Pattern.compile("(security:\\s*\\n)", Pattern.MULTILINE);
        Matcher matcher = securityPattern.matcher(config);

        if (matcher.find()) {
            return matcher.replaceFirst("$1  signature-public-key: \"" + signatureKey + "\"\n");
        } else {
            return config + "\n# Security settings\nsecurity:\n  signature-public-key: \"" + signatureKey + "\"\n";
        }
    }

    private String addSaltToConfig(String config, String salt) {
        Pattern securityPattern = Pattern.compile("(security:\\s*\\n(?:.*\\n)*?)((?:\\S|$))", Pattern.MULTILINE);
        Matcher matcher = securityPattern.matcher(config);

        if (matcher.find()) {
            return matcher.replaceFirst("$1  hardware-fingerprint-salt: \"" + salt + "\"\n$2");
        } else {
            return config + "\n# Security settings\nsecurity:\n  hardware-fingerprint-salt: \"" + salt + "\"\n";
        }
    }

    private void addNewConfigToJar(Path jarPath, String signatureKey, String salt) throws Exception {
        Path tempJarPath = Files.createTempFile("with-config-", ".jar");

        try {
            try (JarInputStream jis = new JarInputStream(new FileInputStream(jarPath.toFile()));
                 JarOutputStream jos = new JarOutputStream(new FileOutputStream(tempJarPath.toFile()))) {
                JarEntry entry;
                byte[] buffer = new byte[8192];

                while ((entry = jis.getNextJarEntry()) != null) {
                    jos.putNextEntry(new JarEntry(entry.getName()));

                    int bytesRead;
                    while ((bytesRead = jis.read(buffer)) != -1) {
                        jos.write(buffer, 0, bytesRead);
                    }

                    jos.closeEntry();
                }

                String newConfig = createDefaultConfig(signatureKey, salt);
                JarEntry configEntry = new JarEntry(CONFIG_YML_PATH);
                jos.putNextEntry(configEntry);
                jos.write(newConfig.getBytes());
                jos.closeEntry();
            }

            Files.move(tempJarPath, jarPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            Files.deleteIfExists(tempJarPath);
            throw e;
        }
    }

    private String createDefaultConfig(String signatureKey, String salt) {
        return "# SecurePluginLoader Configuration\n" +
               "\n" +
               "# Security settings\n" +
               "security:\n" +
               "  signature-public-key: \"" + signatureKey + "\"\n" +
               "  hardware-fingerprint-salt: \"" + salt + "\"\n" +
               "  enable-signature-verification: true\n" +
               "  enable-hardware-fingerprint: true\n";
    }

    public static String generateHardwareFingerprintSalt() {
        byte[] saltBytes = new byte[32];
        new SecureRandom().nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }
}
