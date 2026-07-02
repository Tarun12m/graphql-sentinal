package com.gqlsentinel.model;

/**
 * Finding severity, ordered from most to least serious for stable sorting in the UI/export.
 * Mirrors the vocabulary pentest reports use so exported findings drop straight into a report.
 */
public enum Severity {
    HIGH,
    MEDIUM,
    LOW,
    INFO;

    /** For UI colouring; kept here so the palette is defined once, not per-widget. */
    public String hexColor() {
        return switch (this) {
            case HIGH -> "#c0392b";
            case MEDIUM -> "#e67e22";
            case LOW -> "#f1c40f";
            case INFO -> "#2980b9";
        };
    }
}
