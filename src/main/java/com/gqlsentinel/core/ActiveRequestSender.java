package com.gqlsentinel.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Optional;

/**
 * The one and only path through which active modules send crafted requests.
 *
 * <p>Centralising this enforces, in a single audited place:
 * <ol>
 *   <li>The {@link ScopeGate} check (armed + in-scope) — a module physically cannot send a
 *       request that skips it, because it has no other way to reach the HTTP client.</li>
 *   <li>A polite inter-request delay so we never hammer a target.</li>
 *   <li>Uniform error handling: network failures return {@link Optional#empty()} rather than
 *       throwing, so a module's test loop degrades gracefully on a dropped connection.</li>
 * </ol>
 */
public final class ActiveRequestSender {

    private final ExtensionContext ctx;

    public ActiveRequestSender(ExtensionContext ctx) {
        this.ctx = ctx;
    }

    /**
     * Send a crafted request if and only if active testing is armed and the target is in scope.
     *
     * @return the exchange, or empty if blocked by the scope gate or if the network call failed.
     */
    public Optional<HttpRequestResponse> send(HttpRequest request) {
        if (!ctx.scopeGate().isActiveTestingAllowed(request)) {
            ctx.logger().debug("Blocked an active request (disarmed or out-of-scope): " + safeUrl(request));
            return Optional.empty();
        }
        throttle();
        try {
            HttpRequestResponse rr = ctx.http().sendRequest(request);
            return Optional.ofNullable(rr);
        } catch (RuntimeException e) {
            ctx.logger().warn("Active request failed for " + safeUrl(request) + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Render a request to human-readable text for finding evidence. We assemble it from message
     * components (request line, headers, body) rather than relying on {@code toString()}, whose
     * output is not contractually the raw HTTP message.
     */
    public static String renderRequest(HttpRequest request) {
        if (request == null) {
            return "(no request)";
        }
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(nz(request.method())).append(' ').append(nz(request.path()));
            if (request.httpVersion() != null) {
                sb.append(' ').append(request.httpVersion());
            }
            sb.append('\n');
            request.headers().forEach(h -> sb.append(h.name()).append(": ").append(h.value()).append('\n'));
            String body = request.bodyToString();
            if (body != null && !body.isEmpty()) {
                sb.append('\n').append(body);
            }
            return cap(sb.toString());
        } catch (RuntimeException e) {
            return "(unrenderable request)";
        }
    }

    public static String renderResponse(HttpResponse response) {
        if (response == null) {
            return "(no response)";
        }
        try {
            StringBuilder sb = new StringBuilder();
            if (response.httpVersion() != null) {
                sb.append(response.httpVersion()).append(' ');
            }
            sb.append(response.statusCode()).append(' ').append(nz(response.reasonPhrase())).append('\n');
            response.headers().forEach(h -> sb.append(h.name()).append(": ").append(h.value()).append('\n'));
            String body = response.bodyToString();
            if (body != null && !body.isEmpty()) {
                sb.append('\n').append(body);
            }
            return cap(sb.toString());
        } catch (RuntimeException e) {
            return "(unrenderable response)";
        }
    }

    /** Cap evidence size so a huge body does not bloat the findings store/export. */
    private static String cap(String s) {
        int max = 20_000;
        return s.length() > max ? s.substring(0, max) + "\n...[truncated]..." : s;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private void throttle() {
        int delay = ctx.config().activeRequestDelayMs();
        if (delay > 0) {
            try {
                Thread.sleep(delay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static String safeUrl(HttpRequest request) {
        try {
            return request.url();
        } catch (RuntimeException e) {
            return "(unknown url)";
        }
    }
}
