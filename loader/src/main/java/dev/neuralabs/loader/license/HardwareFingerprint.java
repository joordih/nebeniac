package dev.neuralabs.loader.license;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

/**
 * Enhanced hardware fingerprint generation with multiple signals.
 * SECURITY: While still spoofable, this makes fingerprint forgery significantly harder.
 * 
 * Combines multiple hardware and system identifiers:
 * - MAC addresses (all network interfaces)
 * - CPU information
 * - Disk serial numbers
 * - System UUID
 * - OS details
 * - Server-provided salt (prevents precomputation)
 */
public class HardwareFingerprint {

    private final Logger logger;
    private static final String ALGORITHM = "SHA-256";

    public HardwareFingerprint(Logger logger) {
        this.logger = logger;
    }

    /**
     * Generates a comprehensive hardware fingerprint.
     * 
     * @param serverSalt Salt provided by server to prevent precomputation attacks
     * @return Hexadecimal fingerprint string
     */
    public String generate(String serverSalt) {
        try {
            List<String> components = new ArrayList<>();

            // 1. Network interfaces (MAC addresses)
            components.addAll(getMACAddresses());

            // 2. CPU information
            components.add(getCPUInfo());

            // 3. Disk information
            components.addAll(getDiskInfo());

            // 4. System UUID (if available)
            String systemUUID = getSystemUUID();
            if (systemUUID != null) {
                components.add(systemUUID);
            }

            // 5. OS details
            components.add(System.getProperty("os.name", "unknown"));
            components.add(System.getProperty("os.version", "unknown"));
            components.add(System.getProperty("os.arch", "unknown"));

            // 6. Java runtime
            components.add(System.getProperty("java.version", "unknown"));
            components.add(System.getProperty("java.vendor", "unknown"));

            // 7. User home directory (as additional signal)
            components.add(System.getProperty("user.home", "unknown"));

            // Sort for consistency
            Collections.sort(components);

            // Combine all components with server salt
            StringBuilder combined = new StringBuilder();
            combined.append("SALT:").append(serverSalt).append("|");
            for (String component : components) {
                combined.append(component).append("|");
            }

            // Hash the combined fingerprint
            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            byte[] hash = md.digest(combined.toString().getBytes(StandardCharsets.UTF_8));

            return bytesToHex(hash);

        } catch (Exception e) {
            logger.warning("Error generating hardware fingerprint: " + e.getMessage());
            // Fallback to basic fingerprint
            return generateBasicFingerprint(serverSalt);
        }
    }

    /**
     * Gets all MAC addresses from network interfaces.
     */
    private List<String> getMACAddresses() {
        List<String> macs = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> networks = NetworkInterface.getNetworkInterfaces();
            while (networks.hasMoreElements()) {
                NetworkInterface network = networks.nextElement();
                byte[] mac = network.getHardwareAddress();
                if (mac != null && mac.length > 0) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < mac.length; i++) {
                        sb.append(String.format("%02X%s", mac[i], (i < mac.length - 1) ? "-" : ""));
                    }
                    macs.add("MAC:" + sb.toString());
                }
            }
        } catch (Exception e) {
            logger.fine("Could not retrieve MAC addresses: " + e.getMessage());
        }
        return macs;
    }

    /**
     * Gets CPU information (number of processors and architecture).
     */
    private String getCPUInfo() {
        int processors = Runtime.getRuntime().availableProcessors();
        String arch = System.getProperty("os.arch", "unknown");
        return "CPU:" + processors + ":" + arch;
    }

    /**
     * Gets disk information (available roots and their total space).
     */
    private List<String> getDiskInfo() {
        List<String> disks = new ArrayList<>();
        try {
            File[] roots = File.listRoots();
            for (File root : roots) {
                long totalSpace = root.getTotalSpace();
                if (totalSpace > 0) {
                    disks.add("DISK:" + root.getAbsolutePath() + ":" + totalSpace);
                }
            }
        } catch (Exception e) {
            logger.fine("Could not retrieve disk information: " + e.getMessage());
        }
        return disks;
    }

    /**
     * Attempts to get system UUID (Linux/Windows specific).
     */
    private String getSystemUUID() {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            
            if (os.contains("linux")) {
                return getLinuxSystemUUID();
            } else if (os.contains("windows")) {
                return getWindowsSystemUUID();
            }
        } catch (Exception e) {
            logger.fine("Could not retrieve system UUID: " + e.getMessage());
        }
        return null;
    }

    private String getLinuxSystemUUID() {
        try {
            Process process = Runtime.getRuntime().exec("cat /etc/machine-id");
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String uuid = reader.readLine();
                if (uuid != null && !uuid.isEmpty()) {
                    return "UUID:" + uuid.trim();
                }
            }
        } catch (Exception e) {
            // Try alternative
            try {
                Process process = Runtime.getRuntime().exec("cat /var/lib/dbus/machine-id");
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()))) {
                    String uuid = reader.readLine();
                    if (uuid != null && !uuid.isEmpty()) {
                        return "UUID:" + uuid.trim();
                    }
                }
            } catch (Exception ex) {
                // Ignore
            }
        }
        return null;
    }

    private String getWindowsSystemUUID() {
        try {
            Process process = Runtime.getRuntime().exec("wmic csproduct get uuid");
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.equalsIgnoreCase("UUID")) {
                        return "UUID:" + line;
                    }
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }

    /**
     * Fallback to basic fingerprint if enhanced version fails.
     */
    private String generateBasicFingerprint(String serverSalt) {
        try {
            String osName = System.getProperty("os.name", "unknown");
            String osVersion = System.getProperty("os.version", "unknown");
            String osArch = System.getProperty("os.arch", "unknown");
            String userName = System.getProperty("user.name", "unknown");
            String javaVersion = System.getProperty("java.version", "unknown");

            String combined = serverSalt + "|" + osName + "|" + osVersion + "|" + 
                            osArch + "|" + userName + "|" + javaVersion;

            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            byte[] hash = md.digest(combined.getBytes(StandardCharsets.UTF_8));

            return bytesToHex(hash);
        } catch (Exception e) {
            logger.severe("Failed to generate even basic fingerprint: " + e.getMessage());
            return "fallback-" + System.currentTimeMillis();
        }
    }

    /**
     * Converts byte array to hexadecimal string.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * Validates that a fingerprint matches the current hardware.
     * 
     * @param expectedFingerprint The fingerprint to validate against
     * @param serverSalt The salt used in generation
     * @return true if fingerprint matches
     */
    public boolean validate(String expectedFingerprint, String serverSalt) {
        String currentFingerprint = generate(serverSalt);
        return currentFingerprint.equals(expectedFingerprint);
    }
}
