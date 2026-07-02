package com.gqlsentinel.model;

import java.time.Instant;
import java.util.UUID;

/**
 * A single security finding produced by a module.
 *
 * <p>Deliberately decoupled from Burp types: evidence is stored as plain strings (rendered
 * request/response text) rather than {@code HttpRequestResponse}. This keeps the model
 * serialisable for JSON/HTML export and unit-testable without a Burp runtime, at the cost of
 * holding some duplicated text — an acceptable trade for a findings list that is rarely huge.
 *
 * <p>Built via {@link Builder} because a finding has many optional fields (remediation,
 * evidence) and a telescoping constructor would be unreadable and error-prone.
 */
public final class Finding {

    private final String id;
    private final Instant timestamp;
    private final Severity severity;
    private final String module;
    private final String title;
    private final String description;
    private final String affectedOperation;
    private final String endpointUrl;
    private final String remediation;
    private final String requestEvidence;
    private final String responseEvidence;

    private Finding(Builder b) {
        this.id = UUID.randomUUID().toString();
        this.timestamp = Instant.now();
        this.severity = b.severity;
        this.module = b.module;
        this.title = b.title;
        this.description = b.description;
        this.affectedOperation = b.affectedOperation;
        this.endpointUrl = b.endpointUrl;
        this.remediation = b.remediation;
        this.requestEvidence = b.requestEvidence;
        this.responseEvidence = b.responseEvidence;
    }

    public String id() { return id; }
    public Instant timestamp() { return timestamp; }
    public Severity severity() { return severity; }
    public String module() { return module; }
    public String title() { return title; }
    public String description() { return description; }
    public String affectedOperation() { return affectedOperation; }
    public String endpointUrl() { return endpointUrl; }
    public String remediation() { return remediation; }
    public String requestEvidence() { return requestEvidence; }
    public String responseEvidence() { return responseEvidence; }

    /**
     * De-duplication key. Modules run repeatedly as traffic flows; without this the same missing
     * control would be reported once per observed request. Identity is (module + title + endpoint
     * + operation) — NOT the evidence, which varies per request.
     */
    public String dedupeKey() {
        return module + "|" + title + "|" + endpointUrl + "|" + affectedOperation;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Severity severity = Severity.INFO;
        private String module = "";
        private String title = "";
        private String description = "";
        private String affectedOperation = "";
        private String endpointUrl = "";
        private String remediation = "";
        private String requestEvidence = "";
        private String responseEvidence = "";

        public Builder severity(Severity s) { this.severity = s; return this; }
        public Builder module(String m) { this.module = m; return this; }
        public Builder title(String t) { this.title = t; return this; }
        public Builder description(String d) { this.description = d; return this; }
        public Builder affectedOperation(String o) { this.affectedOperation = o; return this; }
        public Builder endpointUrl(String u) { this.endpointUrl = u; return this; }
        public Builder remediation(String r) { this.remediation = r; return this; }
        public Builder requestEvidence(String r) { this.requestEvidence = r; return this; }
        public Builder responseEvidence(String r) { this.responseEvidence = r; return this; }

        public Finding build() {
            return new Finding(this);
        }
    }
}
