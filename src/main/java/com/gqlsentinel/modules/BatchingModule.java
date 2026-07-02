package com.gqlsentinel.modules;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import com.gqlsentinel.core.ActiveRequestSender;
import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.core.GraphQLRequestBuilder;
import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.model.Finding;
import com.gqlsentinel.model.Severity;

/**
 * Detects whether the endpoint accepts <em>array batching</em> — multiple operations in one HTTP
 * request. Batching lets an attacker collapse many logical requests into one, undermining
 * per-request rate limiting and brute-force protection (e.g. many password attempts per request).
 *
 * <p><b>Capability check only — never a brute-forcer.</b> We send a single request containing a
 * tiny batch (default 3, hard cap {@link com.gqlsentinel.core.Configuration#HARD_MAX_BATCH}) of a
 * completely benign {@code { __typename }} query. We report whether batching is <em>possible</em>;
 * we do not, and this module cannot, iterate credentials or amplify the batch into an attack.
 */
public final class BatchingModule implements AnalysisModule {

    // Benign, side-effect-free operation. __typename resolves on any query root.
    private static final String BENIGN_QUERY = "query { __typename }";

    private final ExtensionContext ctx;
    private final ActiveRequestSender sender;

    public BatchingModule(ExtensionContext ctx, ActiveRequestSender sender) {
        this.ctx = ctx;
        this.sender = sender;
    }

    @Override
    public String name() {
        return "Batching";
    }

    @Override
    public String description() {
        return "Sends one small benign batch to detect whether array batching is accepted "
                + "(which can undermine rate limiting). Capability check only.";
    }

    @Override
    public boolean supportsActive() {
        return true;
    }

    @Override
    public void runActive(DetectedEndpoint endpoint) {
        Optional<HttpRequest> template = firstSampleRequest(endpoint);
        if (template.isEmpty()) {
            ctx.logger().info("Batching: no sample request for " + endpoint.key());
            return;
        }
        int batchSize = ctx.config().probeBatchSize(); // clamped to HARD_MAX_BATCH
        List<String> batch = new ArrayList<>(Collections.nCopies(batchSize, BENIGN_QUERY));
        HttpRequest probe = GraphQLRequestBuilder.batch(template.get(), batch);

        Optional<HttpRequestResponse> result = sender.send(probe);
        if (result.isEmpty()) {
            return;
        }
        HttpResponse response = result.get().response();
        if (response == null) {
            return;
        }

        int responseCount = countBatchResponses(response.bodyToString());
        if (responseCount >= 2) {
            Finding f = Finding.builder()
                    .severity(Severity.MEDIUM)
                    .module(name())
                    .title("GraphQL array batching is accepted")
                    .description("The endpoint accepted a batched request of " + batchSize
                            + " operations and returned " + responseCount + " responses in a single "
                            + "HTTP call. Batching allows an attacker to perform many operations per "
                            + "request, which can bypass per-request rate limiting and brute-force "
                            + "throttling (for example, many login attempts in one request). This "
                            + "check used a benign __typename query and did not attempt any abuse.")
                    .affectedOperation("Batch of " + batchSize + " operations")
                    .endpointUrl(endpoint.url())
                    .remediation("Disable array-based query batching if not required, or apply rate "
                            + "limiting and cost accounting per-operation rather than per-HTTP-request "
                            + "so that batching cannot be used to multiply an attacker's throughput.")
                    .requestEvidence(ActiveRequestSender.renderRequest(result.get().request()))
                    .responseEvidence(ActiveRequestSender.renderResponse(response))
                    .build();
            ctx.findingStore().add(f);
            ctx.logger().info("Batching: endpoint accepted a batch (" + responseCount + " responses).");
        } else {
            ctx.logger().info("Batching: endpoint did not honour array batching (secure). No finding.");
        }
    }

    /** A batched GraphQL response is a JSON array of result objects. Count them; -1 if not an array. */
    private int countBatchResponses(String body) {
        if (body == null || body.isBlank()) {
            return -1;
        }
        try {
            JsonElement el = JsonParser.parseString(body);
            if (!el.isJsonArray()) {
                return -1;
            }
            JsonArray arr = el.getAsJsonArray();
            int valid = 0;
            for (JsonElement item : arr) {
                if (item.isJsonObject()
                        && (item.getAsJsonObject().has("data") || item.getAsJsonObject().has("errors"))) {
                    valid++;
                }
            }
            return valid;
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private Optional<HttpRequest> firstSampleRequest(DetectedEndpoint endpoint) {
        return endpoint.samples().stream()
                .map(HttpRequestResponse::request)
                .filter(r -> r != null)
                .findFirst();
    }
}
