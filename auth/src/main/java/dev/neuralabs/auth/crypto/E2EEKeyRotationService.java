package dev.neuralabs.auth.crypto;

import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.hybrid.HybridConfig;
import com.google.crypto.tink.hybrid.HybridKeyTemplates;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class E2EEKeyRotationService {

    private static final String KEYS_DIR = "keys";
    private static final String ARCHIVE_DIR = "keys/archive";
    private static final String PRIVATE_KEY_FILE =
        "keys/server_private_key.json";
    private static final String PUBLIC_KEY_FILE = "keys/server_public_key.json";
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
        DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    private final ScheduledExecutorService scheduler;
    private final int rotationDays;
    private final boolean autoRotationEnabled;
    private final TinkE2EEManager tinkManager;
    private LocalDateTime lastRotationTime;
    private LocalDateTime nextRotationTime;

        public E2EEKeyRotationService(
        int rotationDays,
        boolean autoRotationEnabled,
        TinkE2EEManager tinkManager
    ) {
        this.rotationDays = rotationDays > 0 ? rotationDays : 30;
        this.autoRotationEnabled = autoRotationEnabled;
        this.tinkManager = tinkManager;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "E2EE-KeyRotation");
            t.setDaemon(true);
            return t;
        });

       
        this.lastRotationTime = getKeyCreationTime();
        this.nextRotationTime = lastRotationTime.plusDays(this.rotationDays);

        if (autoRotationEnabled) {
            scheduleRotation();
            log.info(
                "E2EE Key Rotation Service initialized (rotation every {} days)",
                this.rotationDays
            );
        } else {
            log.info(
                "E2EE Key Rotation Service initialized (manual rotation only)"
            );
        }
    }

        private void scheduleRotation() {
       
        long initialDelaySeconds = calculateInitialDelay();

       
        scheduler.scheduleAtFixedRate(
            this::checkAndRotateKeys,
            initialDelaySeconds,
            TimeUnit.DAYS.toSeconds(1),
            TimeUnit.SECONDS
        );

        log.info(
            "Scheduled automatic key rotation. Next rotation: {}",
            nextRotationTime.format(TIMESTAMP_FORMAT)
        );
    }

        private long calculateInitialDelay() {
        LocalDateTime now = LocalDateTime.now();

        if (now.isAfter(nextRotationTime)) {
           
            return 0;
        }

       
        long secondsUntilRotation = java.time.Duration.between(
            now,
            nextRotationTime
        ).getSeconds();

       
        return Math.min(secondsUntilRotation, TimeUnit.DAYS.toSeconds(1));
    }

        private void checkAndRotateKeys() {
        try {
            LocalDateTime now = LocalDateTime.now();

            if (
                now.isAfter(nextRotationTime) || now.isEqual(nextRotationTime)
            ) {
                log.info("Key rotation due. Rotating keys now...");
                rotateKeys();
            } else {
                log.debug(
                    "Key rotation check: Not due yet. Next rotation: {}",
                    nextRotationTime.format(TIMESTAMP_FORMAT)
                );
            }
        } catch (Exception e) {
            log.error("Error during automatic key rotation check", e);
        }
    }

        public synchronized boolean rotateKeys() {
        try {
            log.info("Starting E2EE key rotation...");

           
            try {
                HybridConfig.register();
            } catch (GeneralSecurityException e) {
               
            }

           
            if (!archiveCurrentKeys()) {
                log.error("Failed to archive current keys");
                return false;
            }

           
            KeysetHandle newPrivateKey = KeysetHandle.generateNew(
                HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
            );
            KeysetHandle newPublicKey = newPrivateKey.getPublicKeysetHandle();

           
            saveKeys(newPrivateKey, newPublicKey);

           
            lastRotationTime = LocalDateTime.now();
            nextRotationTime = lastRotationTime.plusDays(rotationDays);

           
           

            log.info("Key rotation completed successfully");
            log.info(
                "Next rotation scheduled for: {}",
                nextRotationTime.format(TIMESTAMP_FORMAT)
            );

           
            cleanupOldArchives(5);

            return true;
        } catch (Exception e) {
            log.error("Key rotation failed", e);
            return false;
        }
    }

        private boolean archiveCurrentKeys() {
        try {
            File privateKeyFile = new File(PRIVATE_KEY_FILE);
            File publicKeyFile = new File(PUBLIC_KEY_FILE);

            if (!privateKeyFile.exists() || !publicKeyFile.exists()) {
                log.warn("Current keys not found, skipping archive");
                return true;
            }

           
            File archiveDir = new File(ARCHIVE_DIR);
            if (!archiveDir.exists()) {
                archiveDir.mkdirs();
            }

           
            String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);

           
            Path privateSource = privateKeyFile.toPath();
            Path privateArchive = Paths.get(
                ARCHIVE_DIR,
                "server_private_key_" + timestamp + ".json"
            );
            Files.copy(
                privateSource,
                privateArchive,
                StandardCopyOption.REPLACE_EXISTING
            );

           
            Path publicSource = publicKeyFile.toPath();
            Path publicArchive = Paths.get(
                ARCHIVE_DIR,
                "server_public_key_" + timestamp + ".json"
            );
            Files.copy(
                publicSource,
                publicArchive,
                StandardCopyOption.REPLACE_EXISTING
            );

            log.info("Archived current keys with timestamp: {}", timestamp);
            return true;
        } catch (IOException e) {
            log.error("Failed to archive keys", e);
            return false;
        }
    }

        private void saveKeys(KeysetHandle privateKey, KeysetHandle publicKey)
        throws GeneralSecurityException, IOException {
       
        File keysDir = new File(KEYS_DIR);
        if (!keysDir.exists()) {
            keysDir.mkdirs();
        }

       
        try (FileOutputStream fos = new FileOutputStream(PRIVATE_KEY_FILE)) {
            privateKey.writeNoSecret(JsonKeysetWriter.withOutputStream(fos));
        }

       
        try (FileOutputStream fos = new FileOutputStream(PUBLIC_KEY_FILE)) {
            publicKey.writeNoSecret(JsonKeysetWriter.withOutputStream(fos));
        }

        log.info(
            "New keys saved to {} and {}",
            PRIVATE_KEY_FILE,
            PUBLIC_KEY_FILE
        );
    }

        private void cleanupOldArchives(int keepCount) {
        try {
            File archiveDir = new File(ARCHIVE_DIR);
            if (!archiveDir.exists()) {
                return;
            }

           
            List<File> archivedKeys;
            try (Stream<Path> paths = Files.walk(archiveDir.toPath(), 1)) {
                archivedKeys = paths
                    .filter(Files::isRegularFile)
                    .filter(p ->
                        p
                            .getFileName()
                            .toString()
                            .startsWith("server_private_key_")
                    )
                    .map(Path::toFile)
                    .sorted((f1, f2) ->
                        Long.compare(f2.lastModified(), f1.lastModified())
                    )
                    .collect(Collectors.toList());
            }

           
            if (archivedKeys.size() > keepCount) {
                int deleteCount = 0;
                for (int i = keepCount; i < archivedKeys.size(); i++) {
                    File privateArchive = archivedKeys.get(i);
                    String timestamp = extractTimestampFromFilename(
                        privateArchive.getName()
                    );

                    if (timestamp != null) {
                       
                        File publicArchive = new File(
                            archiveDir,
                            "server_public_key_" + timestamp + ".json"
                        );

                        if (privateArchive.delete()) {
                            deleteCount++;
                        }
                        if (publicArchive.exists() && publicArchive.delete()) {
                            log.debug(
                                "Deleted old public key archive: {}",
                                publicArchive.getName()
                            );
                        }
                    }
                }
                log.info("Cleaned up {} old key archives", deleteCount);
            }
        } catch (IOException e) {
            log.warn("Failed to cleanup old archives", e);
        }
    }

        private String extractTimestampFromFilename(String filename) {
       
        if (
            filename.startsWith("server_private_key_") &&
            filename.endsWith(".json")
        ) {
            return filename.substring(19, filename.length() - 5);
        }
        return null;
    }

        private LocalDateTime getKeyCreationTime() {
        try {
            File keyFile = new File(PRIVATE_KEY_FILE);
            if (keyFile.exists()) {
                long lastModified = keyFile.lastModified();
                return LocalDateTime.ofInstant(
                    Instant.ofEpochMilli(lastModified),
                    ZoneId.systemDefault()
                );
            }
        } catch (Exception e) {
            log.warn("Failed to get key creation time", e);
        }
        return LocalDateTime.now();
    }

        public List<String> getArchivedKeyTimestamps() {
        List<String> timestamps = new ArrayList<>();
        try {
            File archiveDir = new File(ARCHIVE_DIR);
            if (archiveDir.exists()) {
                File[] files = archiveDir.listFiles(
                    (dir, name) ->
                        name.startsWith("server_private_key_") &&
                        name.endsWith(".json")
                );

                if (files != null) {
                    for (File file : files) {
                        String timestamp = extractTimestampFromFilename(
                            file.getName()
                        );
                        if (timestamp != null) {
                            timestamps.add(timestamp);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to list archived keys", e);
        }
        timestamps.sort((a, b) -> b.compareTo(a));
        return timestamps;
    }

        public KeyRotationStatus getStatus() {
        return new KeyRotationStatus(
            autoRotationEnabled,
            rotationDays,
            lastRotationTime,
            nextRotationTime,
            getArchivedKeyTimestamps().size(),
            LocalDateTime.now().isAfter(nextRotationTime)
        );
    }

        public void shutdown() {
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
            log.info("E2EE Key Rotation Service shutdown complete");
        } catch (InterruptedException e) {
            scheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

        public static class KeyRotationStatus {

        public final boolean autoRotationEnabled;
        public final int rotationDays;
        public final LocalDateTime lastRotation;
        public final LocalDateTime nextRotation;
        public final int archivedKeyCount;
        public final boolean rotationOverdue;

        public KeyRotationStatus(
            boolean autoRotationEnabled,
            int rotationDays,
            LocalDateTime lastRotation,
            LocalDateTime nextRotation,
            int archivedKeyCount,
            boolean rotationOverdue
        ) {
            this.autoRotationEnabled = autoRotationEnabled;
            this.rotationDays = rotationDays;
            this.lastRotation = lastRotation;
            this.nextRotation = nextRotation;
            this.archivedKeyCount = archivedKeyCount;
            this.rotationOverdue = rotationOverdue;
        }

        @Override
        public String toString() {
            return String.format(
                "KeyRotationStatus{autoEnabled=%s, rotationDays=%d, lastRotation=%s, " +
                    "nextRotation=%s, archived=%d, overdue=%s}",
                autoRotationEnabled,
                rotationDays,
                lastRotation.format(TIMESTAMP_FORMAT),
                nextRotation.format(TIMESTAMP_FORMAT),
                archivedKeyCount,
                rotationOverdue
            );
        }
    }
}
