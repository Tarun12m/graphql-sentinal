package com.gqlsentinel.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A GraphQL endpoint discovered from traffic, plus the privileged sample requests we may replay.
 *
 * <p>Keyed in {@link EndpointRegistry} by host+path. It accumulates a bounded set of observed
 * request/response exchanges so the authorization module has real, in-context queries to replay
 * (synthetic queries would miss server-specific fields and produce noise).
 */
public final class DetectedEndpoint {

    /** Cap on retained samples per endpoint — bounds memory and keeps the replay set focused. */
    private static final int MAX_SAMPLES = 25;

    private final String key;         // host + path, the registry key
    private final String url;         // a representative absolute URL
    private final AtomicReference<String> confidence = new AtomicReference<>("LOW");
    private final AtomicReference<IntrospectionState> introspection =
            new AtomicReference<>(IntrospectionState.UNKNOWN);

    // Copy-on-write: written from the proxy thread, read from UI + active modules.
    private final CopyOnWriteArrayList<HttpRequestResponse> samples = new CopyOnWriteArrayList<>();

    public enum IntrospectionState {
        UNKNOWN, ENABLED, DISABLED
    }

    public DetectedEndpoint(String key, String url) {
        this.key = key;
        this.url = url;
    }

    public String key() { return key; }
    public String url() { return url; }

    public String confidence() { return confidence.get(); }
    public void raiseConfidence(String newConfidence) {
        // Only ever move confidence upward (LOW -> MEDIUM -> HIGH); never downgrade a proven host.
        if (rank(newConfidence) > rank(confidence.get())) {
            confidence.set(newConfidence);
        }
    }

    public IntrospectionState introspection() { return introspection.get(); }
    public void setIntrospection(IntrospectionState state) { introspection.set(state); }

    public List<HttpRequestResponse> samples() {
        return samples;
    }

    /** Add a sample, keeping only the most recent MAX_SAMPLES. */
    public void addSample(HttpRequestResponse exchange) {
        samples.add(exchange);
        while (samples.size() > MAX_SAMPLES) {
            samples.remove(0);
        }
    }

    private static int rank(String c) {
        return switch (c) {
            case "HIGH" -> 3;
            case "MEDIUM" -> 2;
            case "LOW" -> 1;
            default -> 0;
        };
    }
}
