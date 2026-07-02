package com.gqlsentinel.core;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.List;

/**
 * Builds crafted GraphQL requests from an observed template request.
 *
 * <p>Why start from a template instead of {@code HttpRequest.httpRequestFromUrl}? An observed
 * request already carries the correct host, path, TLS/service, and — critically — the ambient
 * headers the server expects (custom API keys, CSRF tokens, host-specific cookies). Reusing it
 * means our probes look like the app's own traffic; only the GraphQL body changes. That both
 * improves accuracy and keeps us from tripping trivial WAF rules that would invalidate results.
 */
public final class GraphQLRequestBuilder {

    /** Single operation as a standard JSON POST envelope. */
    public static HttpRequest single(HttpRequest template, String query, String variablesJson) {
        JsonObject envelope = new JsonObject();
        envelope.addProperty("query", query);
        if (variablesJson != null && !variablesJson.isBlank()) {
            envelope.add("variables", parseOrNull(variablesJson));
        }
        return withJsonBody(template, envelope.toString());
    }

    /** A batch (JSON array) of identical or varied operations, for batching analysis. */
    public static HttpRequest batch(HttpRequest template, List<String> queries) {
        JsonArray arr = new JsonArray();
        for (String q : queries) {
            JsonObject env = new JsonObject();
            env.addProperty("query", q);
            arr.add(env);
        }
        return withJsonBody(template, arr.toString());
    }

    /** Replace method/body/content-type on the template to carry a GraphQL POST. */
    public static HttpRequest withJsonBody(HttpRequest template, String jsonBody) {
        return template
                .withMethod("POST")
                .withUpdatedHeader("Content-Type", "application/json")
                // withBody recomputes Content-Length, so no stale length header is left behind.
                .withBody(jsonBody);
    }

    private static JsonElement parseOrNull(String json) {
        try {
            return JsonParser.parseString(json);
        } catch (RuntimeException e) {
            return JsonParser.parseString("{}");
        }
    }

    private GraphQLRequestBuilder() {
    }
}
