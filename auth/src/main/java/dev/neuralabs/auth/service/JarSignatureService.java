package dev.neuralabs.auth.service;

import lombok.extern.slf4j.Slf4j;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;

/**
 * Service for signing encrypted JAR files with Ed25519 signatures.
 * This replaces the functionality of sign-jar.sh
 */
@Slf4j
public class JarSignatureService {

    private final Ed25519SignatureService signatureService;

    public JarSignatureService(Ed25519SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    /**
     * Signs an encrypted JAR file with Ed25519 signature
     * 
     * @param jarPath Path to the JAR file to sign
     * @return The Base64URL encoded signature
     * @throws Exception if signing fails
     */
    public String signJar(Path jarPath) throws Exception {
        log.info("Signing JAR: {}", jarPath);

        if (!Files.exists(jarPath)) {
            throw new FileNotFoundException("JAR file not found: " + jarPath);
        }

        // Calculate hash of protected files (same algorithm as JarSignatureVerifier)
        byte[] jarHash = calculateJarHash(jarPath);
        log.debug("JAR Hash (hex): {}", bytesToHex(jarHash));

        // Sign the hash with Ed25519
        String signatureBase64Url = signatureService.signToBase64Url(jarHash);
        log.debug("Signature (Base64URL): {}", signatureBase64Url);

        // Add signature to JAR
        addSignatureToJar(jarPath, signatureBase64Url);

        log.info("JAR signed successfully: {}", jarPath);
        log.info("Signature added: NEBENIAC.SIG");

        return signatureBase64Url;
    }

    /**
     * Calculates the SHA-256 hash of protected files in the JAR
     * This must match the algorithm used in JarSignatureVerifier
     */
    private byte[] calculateJarHash(Path jarPath) throws Exception {
        List<String> protectedFiles = new ArrayList<>();
        
        // Extract and list all protected files
        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                
                // Include files that match the protection pattern
                if (name.endsWith(".encrypted") || 
                    name.endsWith(".iv") || 
                    name.equals("plugin.yml") || 
                    name.equals("nebeniac-protection.properties")) {
                    protectedFiles.add(name);
                }
            }
        }

        // Sort files for consistent hashing
        Collections.sort(protectedFiles);
        
        log.debug("Protected files to hash: {}", protectedFiles);

        // Calculate combined hash (filename + content)
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        
        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            for (String fileName : protectedFiles) {
                JarEntry entry = jarFile.getJarEntry(fileName);
                if (entry != null) {
                    // Hash the filename
                    digest.update(fileName.getBytes());
                    
                    // Hash the file content
                    try (InputStream is = jarFile.getInputStream(entry)) {
                        byte[] buffer = new byte[8192];
                        int bytesRead;
                        while ((bytesRead = is.read(buffer)) != -1) {
                            digest.update(buffer, 0, bytesRead);
                        }
                    }
                }
            }
        }

        return digest.digest();
    }

    /**
     * Adds the signature to the JAR file as NEBENIAC.SIG
     */
    private void addSignatureToJar(Path jarPath, String signatureBase64Url) throws Exception {
        Path tempJarPath = Files.createTempFile("signed-jar-", ".jar");
        
        try {
            // Create new JAR with signature
            try (JarInputStream jis = new JarInputStream(new FileInputStream(jarPath.toFile()));
                 JarOutputStream jos = new JarOutputStream(new FileOutputStream(tempJarPath.toFile()))) {
                
                // Copy all existing entries
                JarEntry entry;
                byte[] buffer = new byte[8192];
                
                while ((entry = jis.getNextJarEntry()) != null) {
                    // Skip existing signature if present
                    if (entry.getName().equals("NEBENIAC.SIG")) {
                        continue;
                    }
                    
                    jos.putNextEntry(new JarEntry(entry.getName()));
                    
                    int bytesRead;
                    while ((bytesRead = jis.read(buffer)) != -1) {
                        jos.write(buffer, 0, bytesRead);
                    }
                    
                    jos.closeEntry();
                }
                
                // Add signature entry
                JarEntry sigEntry = new JarEntry("NEBENIAC.SIG");
                jos.putNextEntry(sigEntry);
                jos.write(signatureBase64Url.getBytes());
                jos.closeEntry();
            }
            
            // Replace original JAR with signed JAR
            Files.move(tempJarPath, jarPath, StandardCopyOption.REPLACE_EXISTING);
            
        } catch (Exception e) {
            // Clean up temp file on error
            Files.deleteIfExists(tempJarPath);
            throw e;
        }
    }

    /**
     * Verifies a JAR signature
     */
    public boolean verifyJarSignature(Path jarPath) throws Exception {
        log.info("Verifying JAR signature: {}", jarPath);

        // Extract signature from JAR
        String signature = extractSignatureFromJar(jarPath);
        if (signature == null) {
            log.warn("No signature found in JAR");
            return false;
        }

        // Calculate hash
        byte[] jarHash = calculateJarHash(jarPath);

        // Verify signature
        byte[] signatureBytes = Base64.getUrlDecoder().decode(signature);
        boolean valid = signatureService.verify(jarHash, signatureBytes);

        log.info("Signature verification result: {}", valid ? "VALID" : "INVALID");
        return valid;
    }

    /**
     * Extracts the signature from a JAR file
     */
    private String extractSignatureFromJar(Path jarPath) throws Exception {
        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            JarEntry sigEntry = jarFile.getJarEntry("NEBENIAC.SIG");
            if (sigEntry == null) {
                return null;
            }

            try (InputStream is = jarFile.getInputStream(sigEntry);
                 BufferedReader reader = new BufferedReader(new InputStreamReader(is))) {
                return reader.readLine();
            }
        }
    }

    /**
     * Converts byte array to hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Gets the public key in Base64URL format for configuration
     */
    public String getPublicKeyBase64Url() {
        return signatureService.getPublicKeyBase64Url();
    }
}
