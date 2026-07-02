package com.gqlsentinel.model;

/**
 * One parsed GraphQL operation extracted from an HTTP request.
 *
 * <p>A single HTTP request may carry several of these (a JSON <em>batch</em> array), which is
 * exactly why batching matters for security — so the parser returns a list of these and the
 * batching module counts them.
 *
 * <p>Immutable value object: parsing produces it, modules read it. No behaviour beyond light
 * derivation of {@link OperationType} so callers do not each re-implement the same string sniff.
 */
public final class GraphQLOperation {

    public enum OperationType {
        QUERY, MUTATION, SUBSCRIPTION, UNKNOWN
    }

    private final String query;          // raw GraphQL document text
    private final String operationName;  // may be null
    private final String variablesJson;  // raw JSON for variables, or null
    private final OperationType type;
    private final int batchIndex;        // -1 if not part of a batch, else 0-based position

    public GraphQLOperation(String query, String operationName, String variablesJson, int batchIndex) {
        this.query = query == null ? "" : query;
        this.operationName = operationName;
        this.variablesJson = variablesJson;
        this.batchIndex = batchIndex;
        this.type = sniffType(this.query);
    }

    /**
     * Cheap, allocation-light detection of the operation keyword. GraphQL allows an anonymous
     * shorthand ({@code { field }}) which is always a query. We only read the first meaningful
     * token; full parsing is unnecessary and would be brittle against real-world whitespace.
     */
    private static OperationType sniffType(String query) {
        String trimmed = stripLeadingTrivia(query);
        if (trimmed.startsWith("mutation")) {
            return OperationType.MUTATION;
        }
        if (trimmed.startsWith("subscription")) {
            return OperationType.SUBSCRIPTION;
        }
        if (trimmed.startsWith("query") || trimmed.startsWith("{")) {
            return OperationType.QUERY;
        }
        return OperationType.UNKNOWN;
    }

    /** Skip leading whitespace, BOM, and single-line comments so the keyword sniff is reliable. */
    private static String stripLeadingTrivia(String s) {
        int i = 0;
        int n = s.length();
        while (i < n) {
            char c = s.charAt(i);
            if (Character.isWhitespace(c) || c == '﻿' || c == ',') {
                i++;
            } else if (c == '#') { // GraphQL line comment
                while (i < n && s.charAt(i) != '\n') {
                    i++;
                }
            } else {
                break;
            }
        }
        return s.substring(i);
    }

    public String query() {
        return query;
    }

    public String operationName() {
        return operationName;
    }

    public String variablesJson() {
        return variablesJson;
    }

    public OperationType type() {
        return type;
    }

    public boolean isBatched() {
        return batchIndex >= 0;
    }

    public int batchIndex() {
        return batchIndex;
    }

    /** A short human label for findings/UI, e.g. "mutation login" or "query (anonymous)". */
    public String displayName() {
        String base = type.name().toLowerCase();
        if (operationName != null && !operationName.isBlank()) {
            return base + " " + operationName;
        }
        return base + " (anonymous)";
    }

    /** True for operations that can change server state — never auto-replayed by active modules. */
    public boolean isStateChanging() {
        return type == OperationType.MUTATION || type == OperationType.SUBSCRIPTION;
    }
}
