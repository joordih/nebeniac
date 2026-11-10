package dev.neuralabs.auth.security;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class SecretStore {
  private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");
  private static final Set<PosixFilePermission> OWNER_ONLY_DIR = PosixFilePermissions.fromString("rwx------");
  private static final SecureRandom RANDOM = new SecureRandom();

  private SecretStore() {}

  public static String loadOrCreate(String envVar, String fileName, int randomBytes) {
    String fromEnv = System.getenv(envVar);
    if (fromEnv != null && !fromEnv.isBlank()) {
      return fromEnv.trim();
    }

    Path file = secretsDir().resolve(fileName);
    try {
      if (Files.exists(file)) {
        log.info("{} loaded from {}", envVar, file);
        return Files.readString(file, StandardCharsets.UTF_8).trim();
      }
      return create(file, envVar, randomBytes);
    } catch (FileAlreadyExistsException e) {
      return loadOrCreate(envVar, fileName, randomBytes);
    } catch (IOException e) {
      throw new UncheckedIOException("Cannot load or persist secret " + envVar + " at " + file, e);
    }
  }

  public static void delete(String fileName) {
    Path file = secretsDir().resolve(fileName);
    try {
      Files.deleteIfExists(file);
    } catch (IOException e) {
      log.warn("Could not delete {}: {}", file, e.getMessage());
    }
  }

  private static String create(Path file, String envVar, int randomBytes) throws IOException {
    createDirectory(file.getParent());

    byte[] bytes = new byte[randomBytes];
    RANDOM.nextBytes(bytes);
    String secret = Base64.getEncoder().encodeToString(bytes);

    Files.writeString(file, secret, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    restrict(file, OWNER_ONLY);

    log.warn("{} not provided; generated a new one and stored it in {} (owner-only permissions)", envVar, file);
    return secret;
  }

  private static void createDirectory(Path dir) throws IOException {
    if (Files.isDirectory(dir)) {
      return;
    }
    Files.createDirectories(dir);
    restrict(dir, OWNER_ONLY_DIR);
  }

  private static void restrict(Path path, Set<PosixFilePermission> permissions) throws IOException {
    try {
      Files.setPosixFilePermissions(path, permissions);
    } catch (UnsupportedOperationException e) {
      log.warn("Cannot restrict permissions on {}: POSIX permissions unsupported", path);
    }
  }

  private static Path secretsDir() {
    String dir = System.getenv("NEBENIAC_SECRETS_DIR");
    return Paths.get(dir != null && !dir.isBlank() ? dir.trim() : "data/secrets");
  }
}
