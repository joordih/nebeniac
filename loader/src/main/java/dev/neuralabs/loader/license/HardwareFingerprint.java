package dev.neuralabs.loader.license;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.logging.Logger;

public class HardwareFingerprint {
    private final Logger logger;
    private static final String ALGORITHM = "SHA-256";

    public HardwareFingerprint(Logger logger) {
        this.logger = logger;
    }

    public String generate(String serverSalt) {
        try {
            List<String> components = new ArrayList<>();

            components.addAll(getMACAddresses());

            components.add(getCPUInfo());

            components.addAll(getDiskInfo());

            String systemUUID = getSystemUUID();
            if (systemUUID != null) {
                components.add(systemUUID);
            }

            components.add(System.getProperty("os.name", "unknown"));
            components.add(System.getProperty("os.version", "unknown"));
            components.add(System.getProperty("os.arch", "unknown"));

            components.add(System.getProperty("java.version", "unknown"));
            components.add(System.getProperty("java.vendor", "unknown"));

            components.add(System.getProperty("user.home", "unknown"));

            Collections.sort(components);

            StringBuilder combined = new StringBuilder();
            combined.append("SALT:").append(serverSalt).append("|");
            for (String component : components) {
                combined.append(component).append("|");
            }

            MessageDigest md = MessageDigest.getInstance(ALGORITHM);
            byte[] hash = md.digest(combined.toString().getBytes(StandardCharsets.UTF_8));

            return bytesToHex(hash);
        } catch (Exception e) {
            logger.warning("Error generating hardware fingerprint: " + e.getMessage());

            return generateBasicFingerprint(serverSalt);
        }
    }

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

    private String getCPUInfo() {
        int processors = Runtime.getRuntime().availableProcessors();
        String arch = System.getProperty("os.arch", "unknown");
        return "CPU:" + processors + ":" + arch;
    }

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
        }
        return null;
    }

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

    public boolean validate(String expectedFingerprint, String serverSalt) {
        String currentFingerprint = generate(serverSalt);
        return currentFingerprint.equals(expectedFingerprint);
    }
}
