package dev.neuralabs.auth.service;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.*;
import java.util.jar.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Service for updating config.yml inside encrypted JAR files
 */
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

    /**
     * Updates config.yml inside a JAR file with signature public key and salt
     * 
     * @param jarPath Path to the JAR file
     * @param signaturePublicKey The Ed25519 public key in Base64URL format
     * @param hardwareFingerprintSalt The hardware fingerprint salt
     * @throws Exception if update fails
     */
    public void updateConfigInJar(Path jarPath, String signaturePublicKey, String hardwareFingerprintSalt) 
            throws Exception {
        log.info("Updating config.yml in JAR: {}", jarPath);

        if (!Files.exists(jarPath)) {
            throw new FileNotFoundException("JAR file not found: " + jarPath);
        }

        Path tempJarPath = Files.createTempFile("config-updated-", ".jar");
        
        try {
            boolean configFound = false;
            
            // Create new JAR with updated config
            try (JarInputStream jis = new JarInputStream(new FileInputStream(jarPath.toFile()));
                 JarOutputStream jos = new JarOutputStream(new FileOutputStream(tempJarPath.toFile()))) {
                
                // Copy manifest if present
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
                    
                    // Skip manifest (already added)
                    if (entryName.equals(JarFile.MANIFEST_NAME)) {
                        continue;
                    }
                    
                    // If it's config.yml, update it
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
                        // Copy entry as-is
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
                // If config.yml doesn't exist, create it
                addNewConfigToJar(tempJarPath, signaturePublicKey, hardwareFingerprintSalt);
            }
            
            // Replace original JAR with updated JAR
            Files.move(tempJarPath, jarPath, StandardCopyOption.REPLACE_EXISTING);
            log.info("Successfully updated config.yml in JAR");
            
        } catch (Exception e) {
            // Clean up temp file on error
            Files.deleteIfExists(tempJarPath);
            throw e;
        }
    }

    /**
     * Reads a JAR entry as a string
     */
    private String readEntryAsString(InputStream is) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int bytesRead;
        
        while ((bytesRead = is.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        
        return baos.toString("UTF-8");
    }

    /**
     * Updates the config content with signature key and salt
     */
    private String updateConfigContent(String originalConfig, String signatureKey, String salt) {
        String updated = originalConfig;
        
        // Update or add signature-public-key
        Matcher signatureMatcher = SIGNATURE_KEY_PATTERN.matcher(updated);
        if (signatureMatcher.find()) {
            // Replace existing value
            updated = signatureMatcher.replaceFirst("$1\"" + signatureKey + "\"");
            log.debug("Replaced existing signature-public-key");
        } else {
            // Add to security section if exists
            updated = addSignatureKeyToConfig(updated, signatureKey);
            log.debug("Added new signature-public-key");
        }
        
        // Update or add hardware-fingerprint-salt
        Matcher saltMatcher = SALT_PATTERN.matcher(updated);
        if (saltMatcher.find()) {
            // Replace existing value
            updated = saltMatcher.replaceFirst("$1\"" + salt + "\"");
            log.debug("Replaced existing hardware-fingerprint-salt");
        } else {
            // Add to security section if exists
            updated = addSaltToConfig(updated, salt);
            log.debug("Added new hardware-fingerprint-salt");
        }
        
        return updated;
    }

    /**
     * Adds signature-public-key to config if not present
     */
    private String addSignatureKeyToConfig(String config, String signatureKey) {
        // Look for security section
        Pattern securityPattern = Pattern.compile("(security:\\s*\\n)", Pattern.MULTILINE);
        Matcher matcher = securityPattern.matcher(config);
        
        if (matcher.find()) {
            // Add after security: line
            return matcher.replaceFirst("$1  signature-public-key: \"" + signatureKey + "\"\n");
        } else {
            // Add security section at the end
            return config + "\n# Security settings\nsecurity:\n  signature-public-key: \"" + signatureKey + "\"\n";
        }
    }

    /**
     * Adds hardware-fingerprint-salt to config if not present
     */
    private String addSaltToConfig(String config, String salt) {
        // Look for security section
        Pattern securityPattern = Pattern.compile("(security:\\s*\\n(?:.*\\n)*?)((?:\\S|$))", Pattern.MULTILINE);
        Matcher matcher = securityPattern.matcher(config);
        
        if (matcher.find()) {
            // Add before next section
            return matcher.replaceFirst("$1  hardware-fingerprint-salt: \"" + salt + "\"\n$2");
        } else {
            // Add security section at the end
            return config + "\n# Security settings\nsecurity:\n  hardware-fingerprint-salt: \"" + salt + "\"\n";
        }
    }

    /**
     * Adds a new config.yml to an existing JAR
     */
    private void addNewConfigToJar(Path jarPath, String signatureKey, String salt) throws Exception {
        Path tempJarPath = Files.createTempFile("with-config-", ".jar");
        
        try {
            try (JarInputStream jis = new JarInputStream(new FileInputStream(jarPath.toFile()));
                 JarOutputStream jos = new JarOutputStream(new FileOutputStream(tempJarPath.toFile()))) {
                
                // Copy all existing entries
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
                
                // Add new config.yml
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

    /**
     * Creates a default config.yml with signature key and salt
     */
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

    /**
     * Generates a random hardware fingerprint salt
     */
    public static String generateHardwareFingerprintSalt() {
        byte[] saltBytes = new byte[32];
        new SecureRandom().nextBytes(saltBytes);
        return Base64.getEncoder().encodeToString(saltBytes);
    }
}
