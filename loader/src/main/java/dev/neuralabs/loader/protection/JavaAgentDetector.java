package dev.neuralabs.loader.protection;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.logging.Logger;

/**
 * Detects Java agents and instrumentation attempts.
 * SECURITY: While not foolproof, this raises the bar for attackers trying to
 * intercept class loading or dump decrypted bytecode.
 * 
 * Detection methods:
 * 1. Strong signals: VM arguments, environment flags and JDWP/debug hooks
 * 2. Medium signals: boot/module patching and permissive attach policies
 * 3. Weak signals: internal instrumentation implementations and known agent frameworks
 * 4. Aggregated scoring to stay robust across Java 8-21 with fewer false positives
 */
public class JavaAgentDetector {

    private final Logger logger;
    private boolean detectionEnabled = true;

    public JavaAgentDetector(Logger logger) {
        this.logger = logger;
    }

    private enum JavaProfile {
        LEGACY_8,
        MODERN_9_PLUS
    }

    private JavaProfile getJavaProfile() {
        return getJavaMajorVersion() >= 9 ? JavaProfile.MODERN_9_PLUS : JavaProfile.LEGACY_8;
    }

    private int getJavaMajorVersion() {
        String spec = System.getProperty("java.specification.version", "8");
        if (spec == null) {
            return 8;
        }
        try {
            if (spec.startsWith("1.")) {
                return Integer.parseInt(spec.substring(2));
            }
            return Integer.parseInt(spec);
        } catch (NumberFormatException ex) {
            logger.fine("Could not parse java.specification.version: " + spec);
            return 8;
        }
    }

    private List<String> safeVmArguments() {
        try {
            RuntimeMXBean runtimeMxBean = ManagementFactory.getRuntimeMXBean();
            return runtimeMxBean.getInputArguments();
        } catch (Exception e) {
            logger.fine("Could not read VM arguments: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Performs comprehensive agent detection.
     * 
     * @return Detection result with details
     */
    public DetectionResult detect() {
        if (!detectionEnabled) {
            return new DetectionResult(false, "Detection disabled");
        }

        DetectionResult result = new DetectionResult(false, "No agent signals detected");
        JavaProfile profile = getJavaProfile();
        List<String> vmArguments = safeVmArguments();

        int strongSignals = 0;
        int mediumSignals = 0;
        int weakSignals = 0;

        strongSignals += checkJavaAgentArgs(vmArguments, result);
        strongSignals += checkEnvAgentOptions(result);
        strongSignals += checkJDWP(vmArguments, result);

        if (checkAttachThread(result)) {
            strongSignals++;
        }

        mediumSignals += checkAttachCapabilities(result);
        mediumSignals += checkPatchArgs(vmArguments, profile, result);

        weakSignals += checkInstrumentationImpl(result);
        weakSignals += checkAgentFrameworkHints(result);

        boolean detected = strongSignals >= 1 || mediumSignals >= 2 || weakSignals >= 3;

        result.detected = detected;
        result.message = detected ? "Agent/debug signals detected" : "No agent signals detected";

        if (detected) {
            logger.warning("SECURITY: Agent signals detected (strong=" + strongSignals
                    + ", medium=" + mediumSignals + ", weak=" + weakSignals + ")");
        }

        return result;
    }

    /**
     * Checks VM arguments for agent-related flags that indicate direct instrumentation.
     */
    private int checkJavaAgentArgs(List<String> arguments, DetectionResult result) {
        for (String arg : arguments) {
            String lowerArg = arg.toLowerCase(Locale.ROOT);
            if (lowerArg.startsWith("-javaagent") || lowerArg.startsWith("-agentlib")
                    || lowerArg.startsWith("-agentpath")) {
                result.addDetail("VM argument includes agent flag: " + arg);
                logger.warning("SECURITY: Java agent flag detected: " + arg);
                return 1;
            }
        }
        return 0;
    }

    /**
     * Checks environment variables that can inject agents before the JVM starts.
     */
    private int checkEnvAgentOptions(DetectionResult result) {
        String[] keys = { "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS" };
        for (String key : keys) {
            try {
                String value = System.getenv(key);
                if (value == null || value.isEmpty()) {
                    continue;
                }
                String lowerValue = value.toLowerCase(Locale.ROOT);
                if (lowerValue.contains("-javaagent") || lowerValue.contains("-agentlib")
                        || lowerValue.contains("-agentpath")) {
                    result.addDetail("Environment variable " + key + " contains agent flag: " + value);
                    logger.warning("SECURITY: Environment agent option detected in " + key);
                    return 1;
                }
            } catch (SecurityException ex) {
                logger.fine("Could not read env var " + key + ": " + ex.getMessage());
            }
        }
        return 0;
    }

    /**
     * Checks VM arguments and system properties for JDWP or debugging support.
     */
    private int checkJDWP(List<String> arguments, DetectionResult result) {
        for (String arg : arguments) {
            String lowerArg = arg.toLowerCase(Locale.ROOT);
            if (lowerArg.contains("jdwp") || lowerArg.contains("-xdebug")) {
                result.addDetail("Debugger/JDWP option detected: " + arg);
                logger.warning("SECURITY: Debugger option detected: " + arg);
                return 1;
            }
        }
        try {
            String debugMode = System.getProperty("java.vm.debug");
            if (debugMode != null && debugMode.equalsIgnoreCase("true")) {
                result.addDetail("java.vm.debug system property enabled");
                logger.warning("SECURITY: java.vm.debug enabled");
                return 1;
            }
        } catch (SecurityException e) {
            logger.fine("Could not read java.vm.debug property: " + e.getMessage());
        }
        return 0;
    }

    /**
     * Detects if the Attach Listener thread has been started in this JVM.
     */
    private boolean checkAttachThread(DetectionResult result) {
        try {
            for (Thread thread : Thread.getAllStackTraces().keySet()) {
                if (thread == null) {
                    continue;
                }
                String name = thread.getName();
                if (name != null && name.contains("Attach Listener")) {
                    result.addDetail("Attach listener thread present");
                    logger.warning("SECURITY: Attach listener thread detected");
                    return true;
                }
            }
        } catch (SecurityException e) {
            logger.fine("Could not inspect thread list: " + e.getMessage());
        }
        return false;
    }

    /**
     * Looks for attach-related capabilities enabled via system properties.
     */
    private int checkAttachCapabilities(DetectionResult result) {
        int hits = 0;
        try {
            String allowAttach = System.getProperty("jdk.attach.allowAttachSelf");
            if ("true".equalsIgnoreCase(allowAttach)) {
                result.addDetail("Self-attach enabled via jdk.attach.allowAttachSelf=true");
                logger.info("SECURITY: Self-attach enabled");
                hits++;
            }
        } catch (SecurityException e) {
            logger.fine("Could not read jdk.attach.allowAttachSelf property: " + e.getMessage());
        }
        return hits;
    }

    /**
     * Detects boot or module patching flags that relax module boundaries or override core classes.
     */
    private int checkPatchArgs(List<String> arguments, JavaProfile profile, DetectionResult result) {
        boolean bootPatched = false;
        boolean modulePatched = false;

        for (String arg : arguments) {
            String lowerArg = arg.toLowerCase(Locale.ROOT);
            if (!bootPatched && lowerArg.startsWith("-xbootclasspath")) {
                bootPatched = true;
                result.addDetail("Bootclasspath modified: " + arg);
                logger.info("SECURITY: Bootclasspath modification detected: " + arg);
            }
            if (profile == JavaProfile.MODERN_9_PLUS && !modulePatched
                    && (lowerArg.startsWith("--add-opens") || lowerArg.startsWith("--add-exports")
                            || lowerArg.startsWith("--patch-module"))) {
                modulePatched = true;
                result.addDetail("Module boundaries relaxed: " + arg);
                logger.info("SECURITY: Module access flag detected: " + arg);
            }
        }

        int count = 0;
        if (bootPatched) {
            count++;
        }
        if (modulePatched) {
            count++;
        }
        return count;
    }

    /**
     * Checks for the presence of the internal Instrumentation implementation.
     */
    private int checkInstrumentationImpl(DetectionResult result) {
        try {
            Class.forName("sun.instrument.InstrumentationImpl", false, ClassLoader.getSystemClassLoader());
            result.addDetail("InstrumentationImpl present on classpath");
            logger.fine("InstrumentationImpl detected");
            return 1;
        } catch (ClassNotFoundException e) {
            return 0;
        } catch (LinkageError e) {
            logger.fine("Could not load InstrumentationImpl: " + e.getMessage());
            return 0;
        }
    }

    /**
     * Looks for well-known agent framework classes.
     */
    private int checkAgentFrameworkHints(DetectionResult result) {
        String[] hints = {
                "net.bytebuddy.agent.ByteBuddyAgent",
                "org.aspectj.weaver.loadtime.Agent",
                "com.yourkit.agent.AbstractController",
                "com.newrelic.agent.Agent",
                "com.dynatrace.agent.Agent",
                "com.google.monitoring.runtime.instrumentation.Agent"
        };

        int hits = 0;
        for (String className : hints) {
            try {
                Class.forName(className, false, ClassLoader.getSystemClassLoader());
                result.addDetail("Agent framework class available: " + className);
                logger.fine("Agent framework hint detected: " + className);
                hits++;
            } catch (ClassNotFoundException e) {
                // Not found, continue checking
            } catch (LinkageError e) {
                logger.fine("Error while loading " + className + ": " + e.getMessage());
            }
        }
        return hits;
    }

    /**
     * Attempts to disable Attach mechanism (if possible).
     * Note: This may not work on all JVMs and requires specific permissions.
     */
    public void attemptDisableAttach() {
        try {
            // Try to set system property to disable attach
            System.setProperty("jdk.attach.allowAttachSelf", "false");
            logger.info("Attempted to disable self-attach");
        } catch (SecurityException e) {
            logger.fine("Could not disable attach mechanism: " + e.getMessage());
        }
    }

    /**
     * Enables or disables agent detection.
     */
    public void setDetectionEnabled(boolean enabled) {
        this.detectionEnabled = enabled;
        logger.info("Agent detection " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * Detection result class.
     */
    public static class DetectionResult {
        private boolean detected;
        private String message;
        private final StringBuilder details = new StringBuilder();

        public DetectionResult(boolean detected, String message) {
            this.detected = detected;
            this.message = message;
        }

        public void addDetail(String detail) {
            if (details.length() > 0) {
                details.append("; ");
            }
            details.append(detail);
        }

        public boolean isDetected() {
            return detected;
        }

        public String getMessage() {
            return message;
        }

        public String getDetails() {
            return details.toString();
        }

        @Override
        public String toString() {
            return "DetectionResult{" +
                    "detected=" + detected +
                    ", message='" + message + '\'' +
                    ", details='" + details + '\'' +
                    '}';
        }
    }

    /**
     * Recommended JVM arguments for production to enhance security:
     * -XX:+DisableAttachMechanism
     * -Djdk.attach.allowAttachSelf=false
     * -XX:+UnlockDiagnosticVMOptions
     * -XX:+ShowHiddenFrames (for debugging only)
     */
    public static String getRecommendedJVMArgs() {
        return "-XX:+DisableAttachMechanism -Djdk.attach.allowAttachSelf=false";
    }
}