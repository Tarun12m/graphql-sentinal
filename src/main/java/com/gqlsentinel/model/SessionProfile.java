package com.gqlsentinel.model;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A named authentication context used to replay observed queries as a different principal.
 *
 * <p>The field-level authorization test works by taking a request captured as the HIGH-privilege
 * user and re-issuing it as (a) the LOW-privilege user and (b) an unauthenticated client. This
 * class encapsulates "become that principal": given a template request, produce a copy whose
 * auth material has been swapped for this profile's.
 *
 * <p>Design choices that reduce false positives downstream:
 * <ul>
 *   <li>We REPLACE the whole auth surface (Authorization header + Cookie header + any configured
 *       custom headers) rather than merging. Leftover privileged cookies on a "low-priv" replay
 *       would silently invalidate the entire test, so replacement is the safe default.</li>
 *   <li>{@link Role#UNAUTHENTICATED} strips auth entirely and carries no credentials — it models
 *       the "no session" baseline the spec asks for.</li>
 * </ul>
 */
public final class SessionProfile {

    public enum Role {
        HIGH_PRIV("High-privilege"),
        LOW_PRIV("Low-privilege"),
        UNAUTHENTICATED("Unauthenticated");

        private final String label;
        Role(String label) { this.label = label; }
        public String label() { return label; }
    }

    private final Role role;
    // Ordered so the UI shows headers in the order the user typed them. Values may be blank.
    private final Map<String, String> headers = new LinkedHashMap<>();

    public SessionProfile(Role role) {
        this.role = role;
    }

    public Role role() {
        return role;
    }

    public Map<String, String> headers() {
        return headers;
    }

    /** Convenience for the common cookie/bearer cases the UI exposes as dedicated fields. */
    public void setBearerToken(String token) {
        if (token != null && !token.isBlank()) {
            headers.put("Authorization", "Bearer " + token.trim());
        }
    }

    public void setCookie(String cookie) {
        if (cookie != null && !cookie.isBlank()) {
            headers.put("Cookie", cookie.trim());
        }
    }

    public void putHeader(String name, String value) {
        if (name != null && !name.isBlank()) {
            headers.put(name.trim(), value == null ? "" : value.trim());
        }
    }

    public boolean hasCredentials() {
        return role != Role.UNAUTHENTICATED && !headers.isEmpty();
    }

    /**
     * Produce a copy of {@code template} that presents THIS profile's identity.
     *
     * <p>Steps: (1) strip existing auth-bearing headers so the privileged identity cannot leak
     * through; (2) for authenticated roles, add this profile's headers. Body, method, path and
     * host are preserved exactly so ONLY the identity changes — that isolation is what makes the
     * later response diff attributable to authorization rather than to a different request.
     */
    public HttpRequest applyTo(HttpRequest template) {
        HttpRequest stripped = template
                .withRemovedHeader("Authorization")
                .withRemovedHeader("Cookie");
        if (role == Role.UNAUTHENTICATED) {
            return stripped;
        }
        HttpRequest result = stripped;
        for (Map.Entry<String, String> e : headers.entrySet()) {
            // withUpdatedHeader adds the header if absent or replaces it if present.
            result = result.withUpdatedHeader(e.getKey(), e.getValue());
        }
        return result;
    }
}
