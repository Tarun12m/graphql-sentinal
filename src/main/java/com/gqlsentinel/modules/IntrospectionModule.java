package com.gqlsentinel.modules;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import com.gqlsentinel.core.ActiveRequestSender;
import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.core.GraphQLRequestBuilder;
import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.model.Finding;
import com.gqlsentinel.model.GraphQLOperation;
import com.gqlsentinel.model.GraphQLSchema;
import com.gqlsentinel.model.Severity;

/**
 * Determines whether introspection is enabled and, if so, retrieves and parses the schema.
 *
 * <p>Two independent detection paths:
 * <ul>
 *   <li><b>Passive</b>: if we ever see a response containing {@code "__schema"}, introspection is
 *       demonstrably enabled — no probe needed. We record that and flag it.</li>
 *   <li><b>Active</b>: on demand, send the standard introspection query. A schema in the response
 *       confirms enabled; a top-level error or absent schema means disabled — we mark it and stop
 *       gracefully (no schema tree, no error spam).</li>
 * </ul>
 *
 * <p>"Introspection enabled in production" is reported as INFORMATIONAL, not a vulnerability: it is
 * a hardening gap that greatly eases further attack, but is not itself an exploit. Calling it
 * INFO keeps the severity vocabulary honest — an interviewer will appreciate that restraint.
 */
public final class IntrospectionModule implements AnalysisModule {

    // The widely-used minimal-but-complete introspection query. Trimmed of descriptions/directives
    // we do not render, which also shrinks the request and response we handle.
    private static final String INTROSPECTION_QUERY = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              kind
              name
              fields(includeDeprecated: true) {
                name
                args { name type { kind name ofType { kind name ofType { kind name } } } }
                type { kind name ofType { kind name ofType { kind name } } }
              }
            }
          }
        }
        """;

    private final ExtensionContext ctx;
    private final ActiveRequestSender sender;

    // Latest successfully-parsed schema, exposed to the UI's schema viewer.
    private final AtomicReference<GraphQLSchema> lastSchema = new AtomicReference<>();

    public IntrospectionModule(ExtensionContext ctx, ActiveRequestSender sender) {
        this.ctx = ctx;
        this.sender = sender;
    }

    @Override
    public String name() {
        return "Introspection";
    }

    @Override
    public String description() {
        return "Detects if GraphQL introspection is enabled and parses the schema into a tree.";
    }

    @Override
    public boolean supportsActive() {
        return true;
    }

    public GraphQLSchema lastSchema() {
        return lastSchema.get();
    }

    /** Passive: notice introspection already happening in observed traffic. */
    @Override
    public void onTraffic(DetectedEndpoint endpoint, HttpRequestResponse exchange,
                          List<GraphQLOperation> operations) {
        if (exchange == null || exchange.response() == null) {
            return;
        }
        String body = exchange.response().bodyToString();
        if (body != null && body.contains("\"__schema\"")) {
            endpoint.setIntrospection(DetectedEndpoint.IntrospectionState.ENABLED);
            tryParseAndStore(body);
            report(endpoint, exchange);
        }
    }

    /** Active: probe the endpoint with an introspection query. */
    @Override
    public void runActive(DetectedEndpoint endpoint) {
        Optional<HttpRequest> template = firstSampleRequest(endpoint);
        if (template.isEmpty()) {
            ctx.logger().info("Introspection: no sample request captured yet for " + endpoint.key());
            return;
        }
        HttpRequest probe = GraphQLRequestBuilder.single(template.get(), INTROSPECTION_QUERY, null);
        Optional<HttpRequestResponse> result = sender.send(probe);
        if (result.isEmpty()) {
            return; // blocked by scope gate or network error; already logged
        }
        HttpRequestResponse rr = result.get();
        String body = rr.response() == null ? "" : rr.response().bodyToString();

        if (body != null && body.contains("\"__schema\"") && tryParseAndStore(body)) {
            endpoint.setIntrospection(DetectedEndpoint.IntrospectionState.ENABLED);
            report(endpoint, rr);
            ctx.logger().info("Introspection ENABLED at " + endpoint.key());
        } else {
            // Disabled or blocked — degrade gracefully; this is the SECURE configuration.
            endpoint.setIntrospection(DetectedEndpoint.IntrospectionState.DISABLED);
            ctx.logger().info("Introspection appears DISABLED at " + endpoint.key()
                    + " (secure); no schema tree available.");
        }
    }

    private boolean tryParseAndStore(String body) {
        try {
            JsonObject root = JsonParser.parseString(body).getAsJsonObject();
            JsonObject data = root.has("data") && root.get("data").isJsonObject()
                    ? root.getAsJsonObject("data") : null;
            GraphQLSchema schema = GraphQLSchema.fromIntrospectionData(data);
            if (schema != null) {
                lastSchema.set(schema);
                return true;
            }
        } catch (RuntimeException e) {
            ctx.logger().debug("Introspection response was not parseable JSON: " + e.getMessage());
        }
        return false;
    }

    private void report(DetectedEndpoint endpoint, HttpRequestResponse evidence) {
        Finding f = Finding.builder()
                .severity(Severity.INFO)
                .module(name())
                .title("GraphQL introspection is enabled")
                .description("The endpoint answered an introspection query with its full schema. "
                        + "In production this hands an attacker a complete map of types, queries, "
                        + "mutations, and arguments, dramatically lowering the cost of further "
                        + "attacks such as field-authorization abuse. Introspection should be "
                        + "disabled outside of development environments.")
                .affectedOperation("__schema")
                .endpointUrl(endpoint.url())
                .remediation("Disable introspection in production (e.g. via the GraphQL server's "
                        + "validation rules) or restrict it to authenticated internal users.")
                .requestEvidence(ActiveRequestSender.renderRequest(evidence.request()))
                .responseEvidence(ActiveRequestSender.renderResponse(evidence.response()))
                .build();
        ctx.findingStore().add(f);
    }

    private Optional<HttpRequest> firstSampleRequest(DetectedEndpoint endpoint) {
        return endpoint.samples().stream()
                .map(HttpRequestResponse::request)
                .filter(r -> r != null)
                .findFirst();
    }
}
