package com.gqlsentinel.core;

import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.gqlsentinel.model.GraphQLOperation;

/**
 * Turns an {@link HttpRequest} into zero or more {@link GraphQLOperation}s.
 *
 * <p>Robustness is the whole point of isolating this: real GraphQL traffic arrives in at least
 * four shapes, and hostile/broken bodies are common. Every parse path is wrapped so a malformed
 * body yields an empty list (a non-GraphQL/undecidable request) rather than throwing into a
 * passive proxy handler that runs on every response.
 *
 * <p>Supported shapes:
 * <ol>
 *   <li>POST JSON single: {@code {"query": "...", "variables": {...}, "operationName": "..."}}</li>
 *   <li>POST JSON batch:  {@code [ {...}, {...} ]} — each element becomes an operation.</li>
 *   <li>POST {@code application/graphql}: the raw body IS the query document.</li>
 *   <li>GET with {@code ?query=...&variables=...&operationName=...} (URL-encoded).</li>
 * </ol>
 */
public final class GraphQLRequestParser {

    private final Gson gson = new Gson();
    private final ExtensionLogger logger;

    public GraphQLRequestParser(ExtensionLogger logger) {
        this.logger = logger;
    }

    /** Never throws. Returns an empty list when the request carries no parseable GraphQL. */
    public List<GraphQLOperation> parse(HttpRequest request) {
        try {
            if (request == null) {
                return Collections.emptyList();
            }
            if ("GET".equalsIgnoreCase(request.method())) {
                return parseGetQueryParams(request);
            }
            String contentType = headerValueOrEmpty(request, "Content-Type").toLowerCase();
            String body = request.bodyToString();
            if (body == null || body.isBlank()) {
                return Collections.emptyList();
            }
            if (contentType.contains("application/graphql")) {
                // The entire body is a GraphQL document; no JSON envelope.
                return List.of(new GraphQLOperation(body, null, null, -1));
            }
            return parseJsonBody(body);
        } catch (RuntimeException e) {
            logger.debug("GraphQL parse failed (treated as non-GraphQL): " + e.getMessage());
            return Collections.emptyList();
        }
    }

    private List<GraphQLOperation> parseJsonBody(String body) {
        JsonElement root = JsonParser.parseString(body);
        if (root.isJsonArray()) {
            // Batch: preserve index so the batching module and diffs can reference position.
            List<GraphQLOperation> ops = new ArrayList<>();
            JsonArray arr = root.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                JsonElement el = arr.get(i);
                if (el.isJsonObject()) {
                    GraphQLOperation op = fromEnvelope(el.getAsJsonObject(), i);
                    if (op != null) {
                        ops.add(op);
                    }
                }
            }
            return ops;
        }
        if (root.isJsonObject()) {
            GraphQLOperation op = fromEnvelope(root.getAsJsonObject(), -1);
            return op == null ? Collections.emptyList() : List.of(op);
        }
        return Collections.emptyList();
    }

    /** Extract the standard GraphQL POST envelope. Returns null if there is no "query" field. */
    private GraphQLOperation fromEnvelope(JsonObject obj, int batchIndex) {
        if (!obj.has("query") || obj.get("query").isJsonNull()) {
            return null;
        }
        String query = obj.get("query").getAsString();
        String operationName = obj.has("operationName") && !obj.get("operationName").isJsonNull()
                ? obj.get("operationName").getAsString() : null;
        String variablesJson = obj.has("variables") && !obj.get("variables").isJsonNull()
                ? gson.toJson(obj.get("variables")) : null;
        return new GraphQLOperation(query, operationName, variablesJson, batchIndex);
    }

    private List<GraphQLOperation> parseGetQueryParams(HttpRequest request) {
        String query = null;
        String operationName = null;
        String variablesJson = null;
        for (ParsedHttpParameter p : request.parameters()) {
            // GET-style GraphQL lives in the query string only; ignore cookies/body params.
            if (p.type() != HttpParameterType.URL) {
                continue;
            }
            String name = p.name();
            String value = urlDecode(p.value());
            if ("query".equals(name)) {
                query = value;
            } else if ("operationName".equals(name)) {
                operationName = value;
            } else if ("variables".equals(name)) {
                variablesJson = value;
            }
        }
        if (query == null || query.isBlank()) {
            return Collections.emptyList();
        }
        return List.of(new GraphQLOperation(query, operationName, variablesJson, -1));
    }

    private static String urlDecode(String v) {
        if (v == null) {
            return null;
        }
        try {
            return URLDecoder.decode(v, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return v; // already decoded / not encoded
        }
    }

    private static String headerValueOrEmpty(HttpRequest request, String name) {
        String v = request.headerValue(name);
        return v == null ? "" : v;
    }
}
