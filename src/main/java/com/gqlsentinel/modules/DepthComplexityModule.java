package com.gqlsentinel.modules;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Locale;
import java.util.Optional;

import com.gqlsentinel.core.ActiveRequestSender;
import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.core.GraphQLRequestBuilder;
import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.model.Finding;
import com.gqlsentinel.model.GraphQLSchema;
import com.gqlsentinel.model.Severity;

/**
 * Tests whether the server enforces a query depth / cost limit — a common GraphQL DoS control.
 *
 * <p><b>Deliberately conservative.</b> We send exactly ONE query, nested to a small, hard-capped
 * depth (default 8, absolute ceiling {@link com.gqlsentinel.core.Configuration#HARD_MAX_DEPTH}).
 * We do not ramp up, do not send many requests, and never approach a depth that could realistically
 * exhaust a server. The goal is to demonstrate the <em>absence</em> of a control, not to trigger the
 * outage the control is meant to prevent.
 *
 * <p>Interpretation is honest about its own bound: if the bounded query is accepted, we report only
 * that "no depth/cost limit was enforced at or below depth N" — never the unfalsifiable claim that
 * no limit exists at all. If the server rejects it with a depth/complexity error, that is the SECURE
 * outcome and we say so rather than flagging anything.
 */
public final class DepthComplexityModule implements AnalysisModule {

    private final ExtensionContext ctx;
    private final ActiveRequestSender sender;
    private final IntrospectionModule introspection; // source of the schema needed to build nesting
    private final DepthQueryGenerator generator = new DepthQueryGenerator();

    public DepthComplexityModule(ExtensionContext ctx, ActiveRequestSender sender,
                                 IntrospectionModule introspection) {
        this.ctx = ctx;
        this.sender = sender;
        this.introspection = introspection;
    }

    @Override
    public String name() {
        return "Depth / Complexity";
    }

    @Override
    public String description() {
        return "Sends one bounded, deeply-nested query to check for a missing depth/cost limit. "
                + "Hard-capped so it can never flood the target.";
    }

    @Override
    public boolean supportsActive() {
        return true;
    }

    @Override
    public void runActive(DetectedEndpoint endpoint) {
        GraphQLSchema schema = introspection.lastSchema();
        if (schema == null) {
            ctx.logger().info("Depth/Complexity: no schema available (run introspection first, or "
                    + "introspection is disabled). Cannot construct a nested query; skipping.");
            return;
        }
        Optional<DepthQueryGenerator.SelfReference> ref = generator.findSelfReference(schema);
        if (ref.isEmpty()) {
            ctx.logger().info("Depth/Complexity: schema has no self-referential type reachable "
                    + "without required arguments; cannot build a depth probe safely. Skipping.");
            return;
        }
        Optional<HttpRequest> template = firstSampleRequest(endpoint);
        if (template.isEmpty()) {
            ctx.logger().info("Depth/Complexity: no sample request for " + endpoint.key());
            return;
        }

        int depth = ctx.config().maxProbeDepth(); // already clamped to HARD_MAX_DEPTH
        String query = generator.generate(ref.get(), depth);
        HttpRequest probe = GraphQLRequestBuilder.single(template.get(), query, null);

        Optional<HttpRequestResponse> result = sender.send(probe);
        if (result.isEmpty()) {
            return;
        }
        HttpResponse response = result.get().response();
        if (response == null) {
            return;
        }
        evaluate(endpoint, result.get(), depth);
    }

    private void evaluate(DetectedEndpoint endpoint, HttpRequestResponse rr, int depth) {
        HttpResponse response = rr.response();
        String body = response.bodyToString();
        String lower = body == null ? "" : body.toLowerCase(Locale.ROOT);

        // A response that names depth/complexity/cost is the server telling us it rejected the
        // query for exceeding a limit — i.e. the control is present. Treat that as the secure
        // outcome regardless of exact status code (servers vary: 200+errors, 400, 403...).
        boolean limitError = lower.contains("depth")
                || lower.contains("complexity")
                || lower.contains("query cost")
                || lower.contains("too deep")
                || (lower.contains("maximum") && lower.contains("exceed"));

        if (limitError) {
            ctx.logger().info("Depth/Complexity: server rejected a depth-" + depth
                    + " query (a limit appears to be enforced). No finding.");
            return;
        }

        // No limit signal: did the deep query actually execute and return data?
        boolean acceptedWithData = body != null && body.contains("\"data\"");
        if (acceptedWithData) {
            Finding f = Finding.builder()
                    .severity(Severity.MEDIUM)
                    .module(name())
                    .title("No query depth/cost limit enforced (up to depth " + depth + ")")
                    .description("The server accepted a query nested to depth " + depth + " and "
                            + "returned data without rejecting it for depth or complexity. GraphQL "
                            + "endpoints without a depth or cost limit are vulnerable to denial of "
                            + "service via a single, cheaply-constructed deeply-nested query. This "
                            + "probe was intentionally bounded to depth " + depth + " for safety and "
                            + "did not attempt to exhaust the server.")
                    .affectedOperation("DepthProbe (depth " + depth + ")")
                    .endpointUrl(endpoint.url())
                    .remediation("Enforce a maximum query depth and/or a query cost/complexity "
                            + "budget (e.g. graphql-depth-limit, query cost analysis) and reject "
                            + "queries that exceed it before execution.")
                    .requestEvidence(ActiveRequestSender.renderRequest(rr.request()))
                    .responseEvidence(ActiveRequestSender.renderResponse(response))
                    .build();
            ctx.findingStore().add(f);
        } else {
            ctx.logger().info("Depth/Complexity: inconclusive response at depth " + depth
                    + " (status " + response.statusCode() + "); no finding raised.");
        }
    }

    private Optional<HttpRequest> firstSampleRequest(DetectedEndpoint endpoint) {
        return endpoint.samples().stream()
                .map(HttpRequestResponse::request)
                .filter(r -> r != null)
                .findFirst();
    }
}
