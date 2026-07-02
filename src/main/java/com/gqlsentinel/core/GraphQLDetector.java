package com.gqlsentinel.core;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;
import java.util.Locale;

import com.gqlsentinel.model.GraphQLOperation;

/**
 * Passive heuristic classifier: "is this HTTP exchange a GraphQL request?"
 *
 * <p>Detection deliberately combines several weak signals rather than trusting any one, because
 * each on its own produces false positives:
 * <ul>
 *   <li><b>Path</b> ({@code /graphql}, {@code /api/graphql}, {@code /gql}, {@code /query}) — common
 *       but not guaranteed; some deployments hide GraphQL behind arbitrary paths.</li>
 *   <li><b>Content-Type</b> ({@code application/graphql}) — strong but rarely used in practice.</li>
 *   <li><b>Body shape</b> — a successfully parsed {@code query}/mutation envelope is the strongest
 *       positive signal and works regardless of path.</li>
 *   <li><b>Response shape</b> — GraphQL always answers with a top-level {@code data} and/or
 *       {@code errors} object, even for failures, which distinguishes it from REST.</li>
 * </ul>
 *
 * <p>We return a graded {@link Confidence} instead of a bare boolean so the UI can show WHY a
 * host was flagged and the operator can trust/untrust it. This is an intentional anti-false-
 * positive measure: we never auto-arm active testing off a weak (path-only) signal.
 */
public final class GraphQLDetector {

    public enum Confidence {
        NONE,        // not GraphQL as far as we can tell
        LOW,         // a single weak signal (e.g. path only)
        MEDIUM,      // path + plausible envelope, or content-type alone
        HIGH         // parsed a real operation, or a GraphQL-shaped response
    }

    /** Result of classifying one exchange: the verdict plus a short human explanation. */
    public record Detection(Confidence confidence, String reason) {
        public boolean isGraphQL() {
            return confidence != Confidence.NONE;
        }
    }

    private static final List<String> GRAPHQL_PATH_HINTS =
            List.of("/graphql", "/api/graphql", "/graphql/console", "/gql", "/query", "/v1/graphql");

    private final GraphQLRequestParser parser;

    public GraphQLDetector(GraphQLRequestParser parser) {
        this.parser = parser;
    }

    /**
     * Classify using request and (optional) response. Response is a strong corroborator but not
     * required, so this also works when only a request is available (e.g. from the site map).
     */
    public Detection detect(HttpRequest request, HttpResponse response) {
        if (request == null) {
            return new Detection(Confidence.NONE, "no request");
        }

        boolean pathHit = pathLooksLikeGraphQL(request);
        boolean contentTypeHit = requestContentTypeIsGraphQL(request);

        // Strongest signal: we actually parsed a GraphQL operation out of the body/query string.
        List<GraphQLOperation> ops = parser.parse(request);
        boolean parsedOperation = !ops.isEmpty()
                && ops.stream().anyMatch(o -> o.type() != GraphQLOperation.OperationType.UNKNOWN);

        boolean responseShapeHit = responseLooksLikeGraphQL(response);

        // Combine. A parsed operation OR a GraphQL-shaped response is HIGH confidence.
        if (parsedOperation && (responseShapeHit || pathHit || contentTypeHit)) {
            return new Detection(Confidence.HIGH, "parsed a GraphQL operation with corroborating signal");
        }
        if (parsedOperation) {
            return new Detection(Confidence.HIGH, "parsed a GraphQL operation from the request body");
        }
        if (responseShapeHit && (pathHit || contentTypeHit)) {
            return new Detection(Confidence.HIGH, "GraphQL-shaped response on a GraphQL-like endpoint");
        }
        if (contentTypeHit) {
            return new Detection(Confidence.MEDIUM, "request Content-Type is application/graphql");
        }
        if (responseShapeHit) {
            return new Detection(Confidence.MEDIUM, "response has top-level data/errors envelope");
        }
        if (pathHit) {
            // Path alone is weak: /query etc. is common in non-GraphQL APIs too.
            return new Detection(Confidence.LOW, "URL path resembles a GraphQL endpoint");
        }
        return new Detection(Confidence.NONE, "no GraphQL signals");
    }

    private boolean pathLooksLikeGraphQL(HttpRequest request) {
        String path = request.path();
        if (path == null) {
            return false;
        }
        String lower = path.toLowerCase(Locale.ROOT);
        // Strip query string before matching so ?query=... does not spuriously match "/query".
        int q = lower.indexOf('?');
        if (q >= 0) {
            lower = lower.substring(0, q);
        }
        for (String hint : GRAPHQL_PATH_HINTS) {
            if (lower.equals(hint) || lower.endsWith(hint)) {
                return true;
            }
        }
        return false;
    }

    private boolean requestContentTypeIsGraphQL(HttpRequest request) {
        String ct = request.headerValue("Content-Type");
        return ct != null && ct.toLowerCase(Locale.ROOT).contains("application/graphql");
    }

    /**
     * A GraphQL response is JSON with a top-level "data" and/or "errors" key. We check cheaply on
     * the raw string (no full JSON parse on every proxied response) but require the JSON to at
     * least start like an object so we do not match REST bodies that merely contain the word.
     */
    private boolean responseLooksLikeGraphQL(HttpResponse response) {
        if (response == null) {
            return false;
        }
        String mime = response.headerValue("Content-Type");
        if (mime != null && !mime.toLowerCase(Locale.ROOT).contains("json")) {
            return false;
        }
        String body = response.bodyToString();
        if (body == null) {
            return false;
        }
        String trimmed = body.stripLeading();
        if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
            return false;
        }
        // Look only at the leading window to keep this O(1)-ish on large responses.
        String head = trimmed.length() > 512 ? trimmed.substring(0, 512) : trimmed;
        return head.contains("\"data\"") || head.contains("\"errors\"");
    }
}
