package com.gqlsentinel.core;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.List;

import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.model.Finding;
import com.gqlsentinel.model.GraphQLOperation;
import com.gqlsentinel.model.Severity;
import com.gqlsentinel.modules.ModuleRegistry;

/**
 * The passive entry point: a proxy response handler that observes real browsing traffic, gates it
 * through scope, decides whether it is GraphQL, records the endpoint, and fans it out to the
 * modules' passive hooks.
 *
 * <p>Why the PROXY response handler (not a general HTTP handler)? Proxy traffic is exactly the
 * user's in-browser activity — the requests we are authorised to observe. A general HTTP handler
 * would also see our OWN active probes and Scanner/Repeater traffic, which we do not want to
 * re-ingest. Using the proxy hook keeps passive detection tied to genuine target interaction.
 *
 * <p>This handler is on the hot path for every proxied response, so it is written to be cheap and
 * to never throw: the scope check short-circuits out-of-scope hosts immediately, and detection
 * runs cheap heuristics before any parsing.
 */
public final class PassiveDetectionHandler implements ProxyResponseHandler {

    private final ExtensionContext ctx;
    private final ModuleRegistry modules;

    public PassiveDetectionHandler(ExtensionContext ctx, ModuleRegistry modules) {
        this.ctx = ctx;
        this.modules = modules;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
        try {
            analyse(interceptedResponse);
        } catch (RuntimeException e) {
            // Absolutely never break the user's proxy over an analysis bug.
            ctx.logger().debug("Passive detection error (ignored): " + e.getMessage());
        }
        // Passive: we observe only, never modify the response.
        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    private void analyse(InterceptedResponse response) {
        HttpRequest request = response.initiatingRequest();
        if (request == null) {
            return;
        }

        // SCOPE GATE FIRST. We do not even classify out-of-scope traffic — cheapest and safest.
        if (!ctx.scopeGate().isInScope(request)) {
            return;
        }

        GraphQLDetector.Detection detection = ctx.detector().detect(request, response);
        if (!detection.isGraphQL()) {
            return;
        }
        // Ignore the weakest (path-only) signal for passive recording to avoid registering random
        // /query REST endpoints. MEDIUM+ requires an actual envelope or GraphQL-shaped response.
        if (detection.confidence() == GraphQLDetector.Confidence.LOW) {
            return;
        }

        String host = request.httpService().host();
        String path = stripQuery(request.path());
        String url = request.url();

        HttpRequestResponse exchange = HttpRequestResponse.httpRequestResponse(request, response);
        boolean isNew = ctx.endpointRegistry().get(host + path) == null;
        DetectedEndpoint endpoint = ctx.endpointRegistry()
                .record(host, path, url, detection.confidence().name(), exchange);

        List<GraphQLOperation> operations = ctx.parser().parse(request);

        if (isNew) {
            ctx.logger().info("Detected GraphQL endpoint [" + detection.confidence() + "]: " + url
                    + " (" + detection.reason() + ")");
            raiseEndpointFinding(endpoint, detection, exchange);
        }

        // Fan out to passive module hooks (introspection sniff, injection-surface mapping, ...).
        modules.dispatchPassive(endpoint, exchange, operations);
    }

    private void raiseEndpointFinding(DetectedEndpoint endpoint, GraphQLDetector.Detection detection,
                                      HttpRequestResponse exchange) {
        Finding f = Finding.builder()
                .severity(Severity.INFO)
                .module("Detection")
                .title("GraphQL endpoint detected")
                .description("A GraphQL endpoint was observed in in-scope proxy traffic. "
                        + "Detection confidence: " + detection.confidence() + " (" + detection.reason()
                        + "). This endpoint is now available for the analysis modules.")
                .affectedOperation("(endpoint discovery)")
                .endpointUrl(endpoint.url())
                .remediation("N/A — informational. Ensure GraphQL-specific controls (introspection "
                        + "off in prod, depth/cost limits, field-level authorization) are in place.")
                .requestEvidence(ActiveRequestSender.renderRequest(exchange.request()))
                .responseEvidence(ActiveRequestSender.renderResponse(exchange.response()))
                .build();
        ctx.findingStore().add(f);
    }

    private static String stripQuery(String path) {
        if (path == null) {
            return "";
        }
        int q = path.indexOf('?');
        return q >= 0 ? path.substring(0, q) : path;
    }
}
