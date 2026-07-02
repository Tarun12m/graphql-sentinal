package com.gqlsentinel.model;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Thread-safe map of discovered GraphQL endpoints. Single source of truth shared by the passive
 * detector (writer), the UI (reader), and the active modules (readers of the sample requests).
 */
public final class EndpointRegistry {

    private final Map<String, DetectedEndpoint> endpoints = new ConcurrentHashMap<>();
    private final List<Consumer<DetectedEndpoint>> listeners = new CopyOnWriteArrayList<>();

    /**
     * Record an observed GraphQL exchange, creating the endpoint entry if new. Returns the
     * endpoint so the caller can update introspection state etc.
     */
    public DetectedEndpoint record(String host, String path, String url,
                                   String confidence, HttpRequestResponse exchange) {
        String key = host + path;
        DetectedEndpoint endpoint = endpoints.computeIfAbsent(key, k -> new DetectedEndpoint(k, url));
        boolean isNew = endpoint.samples().isEmpty();
        endpoint.raiseConfidence(confidence);
        if (exchange != null) {
            endpoint.addSample(exchange);
        }
        if (isNew) {
            notifyListeners(endpoint);
        }
        return endpoint;
    }

    public List<DetectedEndpoint> all() {
        return new ArrayList<>(endpoints.values());
    }

    public DetectedEndpoint get(String key) {
        return endpoints.get(key);
    }

    public int size() {
        return endpoints.size();
    }

    public void addListener(Consumer<DetectedEndpoint> listener) {
        listeners.add(listener);
    }

    private void notifyListeners(DetectedEndpoint endpoint) {
        for (Consumer<DetectedEndpoint> l : listeners) {
            try {
                l.accept(endpoint);
            } catch (RuntimeException ignored) {
                // UI listener failures must not corrupt the registry.
            }
        }
    }
}
