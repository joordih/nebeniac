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

@Slf4j
public class JarSignatureService {
    private final Ed25519SignatureService signatureService;

    public JarSignatureService(Ed25519SignatureService signatureService) {
        this.signatureService = signatureService;
    }

    public String signJar(Path jarPath) throws Exception {
        log.info("Signing JAR: {}", jarPath);

        if (!Files.exists(jarPath)) {
            throw new FileNotFoundException("JAR file not found: " + jarPath);
        }

        byte[] jarHash = calculateJarHash(jarPath);
        log.debug("JAR Hash (hex): {}", bytesToHex(jarHash));

        String signatureBase64Url = signatureService.signToBase64Url(jarHash);
        log.debug("Signature (Base64URL): {}", signatureBase64Url);

        addSignatureToJar(jarPath, signatureBase64Url);

        log.info("JAR signed successfully: {}", jarPath);
        log.info("Signature added: NEBENIAC.SIG");

        return signatureBase64Url;
    }

    private byte[] calculateJarHash(Path jarPath) throws Exception {
        List<String> protectedFiles = new ArrayList<>();

        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                if (name.endsWith(".encrypted") ||
                    name.endsWith(".iv") ||
                    name.equals("plugin.yml")) {
                    protectedFiles.add(name);
                }
            }
        }

        Collections.sort(protectedFiles);

        log.debug("Protected files to hash: {}", protectedFiles);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            for (String fileName : protectedFiles) {
                JarEntry entry = jarFile.getJarEntry(fileName);
                if (entry != null) {
                    digest.update(fileName.getBytes());

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

    private void addSignatureToJar(Path jarPath, String signatureBase64Url) throws Exception {
        Path tempJarPath = Files.createTempFile("signed-jar-", ".jar");

        try {
            try (JarInputStream jis = new JarInputStream(new FileInputStream(jarPath.toFile()));
                 JarOutputStream jos = new JarOutputStream(new FileOutputStream(tempJarPath.toFile()))) {
                JarEntry entry;
                byte[] buffer = new byte[8192];

                while ((entry = jis.getNextJarEntry()) != null) {
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

                JarEntry sigEntry = new JarEntry("NEBENIAC.SIG");
                jos.putNextEntry(sigEntry);
                jos.write(signatureBase64Url.getBytes());
                jos.closeEntry();
            }

            Files.move(tempJarPath, jarPath, StandardCopyOption.REPLACE_EXISTING);
        } catch (Exception e) {
            Files.deleteIfExists(tempJarPath);
            throw e;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public String getPublicKeyBase64Url() {
        return signatureService.getPublicKeyBase64Url();
    }
}
