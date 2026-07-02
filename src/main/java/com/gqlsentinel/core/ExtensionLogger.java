package com.gqlsentinel.core;

import burp.api.montoya.logging.Logging;

import java.time.Instant;

/**
 * Thin, structured logging facade over Montoya's {@link Logging}.
 *
 * <p>Design: every module logs through this one class rather than calling
 * {@code api.logging()} directly. Benefits:
 * <ul>
 *   <li>Consistent, timestamped, level-prefixed lines that are greppable in Burp's
 *       "Output"/"Errors" tabs.</li>
 *   <li>A single {@code debug} gate so verbose per-request tracing can be toggled
 *       from the UI without threading a boolean through every class.</li>
 *   <li>One seam to redirect logs in unit tests.</li>
 * </ul>
 * Intentionally minimal — this is a Burp extension, not a service; we do not pull in
 * SLF4J/Logback (extra bundled deps, classloader risk) for what three methods cover.
 */
public final class ExtensionLogger {

    private final Logging logging;
    private volatile boolean debugEnabled;

    public ExtensionLogger(Logging logging) {
        this.logging = logging;
        this.debugEnabled = false;
    }

    public void setDebugEnabled(boolean enabled) {
        this.debugEnabled = enabled;
        info("Debug logging " + (enabled ? "ENABLED" : "disabled"));
    }

    public boolean isDebugEnabled() {
        return debugEnabled;
    }

    /** High-signal operational messages (module started, finding raised, etc.). */
    public void info(String message) {
        logging.logToOutput(format("INFO", message));
    }

    /** Per-request/verbose tracing. Suppressed unless debug is enabled to avoid log spam. */
    public void debug(String message) {
        if (debugEnabled) {
            logging.logToOutput(format("DEBUG", message));
        }
    }

    public void warn(String message) {
        logging.logToOutput(format("WARN", message));
    }

    /** Errors go to Burp's dedicated error stream so they are not lost among output. */
    public void error(String message) {
        logging.logToError(format("ERROR", message));
    }

    public void error(String message, Throwable t) {
        logging.logToError(format("ERROR", message + " :: " + t.getClass().getSimpleName() + ": " + t.getMessage()));
    }

    private String format(String level, String message) {
        return "[" + Instant.now() + "][GQL-Sentinel][" + level + "] " + message;
    }
}
