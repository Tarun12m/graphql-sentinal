package com.gqlsentinel.modules;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.gqlsentinel.core.ActiveRequestSender;
import com.gqlsentinel.core.ExtensionContext;
import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.model.Finding;
import com.gqlsentinel.model.GraphQLOperation;
import com.gqlsentinel.model.SessionProfile;
import com.gqlsentinel.model.Severity;

/**
 * THE differentiator: field/object-level authorization testing.
 *
 * <p>Idea: the operator browses the target as the HIGH-privilege user; that traffic is captured as
 * per-endpoint samples. On demand, this module re-issues each observed <em>query</em> as the
 * configured LOW-privilege session and as an UNAUTHENTICATED client, then diffs each replay
 * against the privileged baseline with {@link AuthzComparator}. Any baseline field the lower
 * principal could also read is a candidate authorization gap.
 *
 * <h2>Safety and correctness decisions</h2>
 * <ul>
 *   <li><b>Read-only.</b> Mutations and subscriptions are never replayed (they change state). A
 *       sample containing any state-changing operation is skipped entirely unless the operator has
 *       explicitly opted in via configuration — off by default.</li>
 *   <li><b>Identity is the only variable.</b> We replay the exact captured request and swap ONLY
 *       the auth material (see {@link SessionProfile#applyTo}). Because nothing else changes, a
 *       response difference is attributable to authorization, not to a different query.</li>
 *   <li><b>Baseline gating.</b> We only test samples whose privileged response was a 2xx with
 *       data; there is nothing to "leak" from an error baseline.</li>
 * </ul>
 */
public final class FieldAuthorizationModule implements AnalysisModule {

    private final ExtensionContext ctx;
    private final ActiveRequestSender sender;
    private final AuthzComparator comparator = new AuthzComparator();

    public FieldAuthorizationModule(ExtensionContext ctx, ActiveRequestSender sender) {
        this.ctx = ctx;
        this.sender = sender;
    }

    @Override
    public String name() {
        return "Field Authorization";
    }

    @Override
    public String description() {
        return "Replays observed privileged queries as low-priv and unauthenticated principals "
                + "and diffs responses to find fields a lower user can access but shouldn't.";
    }

    @Override
    public boolean supportsActive() {
        return true;
    }

    @Override
    public void runActive(DetectedEndpoint endpoint) {
        // Build the list of lower principals to test against the privileged baseline.
        List<SessionProfile> lowerPrincipals = new ArrayList<>();
        if (ctx.lowPrivSession().hasCredentials()) {
            lowerPrincipals.add(ctx.lowPrivSession());
        } else {
            ctx.logger().info("Field Authorization: no low-priv session configured; "
                    + "testing the unauthenticated principal only.");
        }
        // The "no session" baseline is always tested — it needs no configuration.
        lowerPrincipals.add(new SessionProfile(SessionProfile.Role.UNAUTHENTICATED));

        int tested = 0;
        for (HttpRequestResponse sample : List.copyOf(endpoint.samples())) {
            if (!isViableBaseline(sample)) {
                continue;
            }
            List<GraphQLOperation> ops = ctx.parser().parse(sample.request());
            if (shouldSkipForStateChange(ops)) {
                ctx.logger().debug("Skipping a sample containing a state-changing operation.");
                continue;
            }
            String opLabel = ops.isEmpty() ? "query" : ops.get(0).displayName();

            for (SessionProfile principal : lowerPrincipals) {
                testOneReplay(endpoint, sample, opLabel, principal);
                tested++;
            }
        }
        ctx.logger().info("Field Authorization: ran " + tested + " replay comparison(s) for "
                + endpoint.key());
    }

    private void testOneReplay(DetectedEndpoint endpoint, HttpRequestResponse sample,
                               String opLabel, SessionProfile principal) {
        HttpRequest replay = principal.applyTo(sample.request());
        Optional<HttpRequestResponse> result = sender.send(replay);
        if (result.isEmpty()) {
            return; // scope-gated or network error
        }
        HttpResponse baseline = sample.response();
        HttpResponse lower = result.get().response();
        if (lower == null) {
            return;
        }

        AuthzComparator.Result cmp = comparator.compare(
                baseline.statusCode(), baseline.bodyToString(),
                lower.statusCode(), lower.bodyToString());

        if (!cmp.isLeak()) {
            ctx.logger().debug("No authz gap for " + opLabel + " as " + principal.role().label()
                    + " (" + cmp.rationale() + ")");
            return;
        }

        for (AuthzComparator.LeakedField leak : cmp.leakedFields()) {
            ctx.findingStore().add(buildFinding(endpoint, sample, result.get(),
                    opLabel, principal, leak));
        }
    }

    private Finding buildFinding(DetectedEndpoint endpoint,
                                 HttpRequestResponse baseline,
                                 HttpRequestResponse replay,
                                 String opLabel,
                                 SessionProfile principal,
                                 AuthzComparator.LeakedField leak) {
        // Confidence grading: identical values are a definite leak of the SAME object (HIGH).
        // Different non-null values mean the field is reachable but may be legitimately row-scoped
        // to the lower user, so we downgrade and explicitly ask for manual confirmation (MEDIUM).
        Severity severity = leak.identicalValue() ? Severity.HIGH : Severity.MEDIUM;
        String confidenceNote = leak.identicalValue()
                ? "The lower principal received the SAME value as the privileged baseline, which "
                  + "is a direct leak of privileged data."
                : "The lower principal received a non-null value for this field that differs from "
                  + "the baseline. The field is reachable without the required privilege; confirm "
                  + "manually whether the returned data is sensitive or merely the lower user's own.";

        return Finding.builder()
                .severity(severity)
                .module(name())
                .title("Field accessible to " + principal.role().label().toLowerCase()
                        + " principal: '" + leak.name() + "'")
                .description("The field '" + leak.name() + "' was returned to a "
                        + principal.role().label().toLowerCase() + " principal replaying a query "
                        + "that was originally observed for the privileged user. " + confidenceNote)
                .affectedOperation(opLabel + " → field '" + leak.name() + "' as "
                        + principal.role().label())
                .endpointUrl(endpoint.url())
                .remediation("Enforce authorization at the field/object resolver level, not just at "
                        + "the endpoint. Verify the acting principal's privileges before resolving "
                        + "'" + leak.name() + "', and return an authorization error (not the data) "
                        + "when the check fails.")
                .requestEvidence("PRIVILEGED BASELINE REQUEST:\n"
                        + ActiveRequestSender.renderRequest(baseline.request())
                        + "\n\n----- REPLAYED AS " + principal.role().label().toUpperCase()
                        + " -----\n" + ActiveRequestSender.renderRequest(replay.request()))
                .responseEvidence("PRIVILEGED BASELINE RESPONSE:\n"
                        + ActiveRequestSender.renderResponse(baseline.response())
                        + "\n\n----- " + principal.role().label().toUpperCase() + " RESPONSE -----\n"
                        + ActiveRequestSender.renderResponse(replay.response()))
                .build();
    }

    /** A usable baseline is a 2xx response that actually carried a body to diff against. */
    private boolean isViableBaseline(HttpRequestResponse sample) {
        if (sample == null || sample.request() == null || sample.response() == null) {
            return false;
        }
        int status = sample.response().statusCode();
        String body = sample.response().bodyToString();
        return status >= 200 && status < 300 && body != null && body.contains("\"data\"");
    }

    /** Skip if any operation mutates state and the operator hasn't opted into replaying those. */
    private boolean shouldSkipForStateChange(List<GraphQLOperation> ops) {
        if (ctx.config().allowStateChangingReplay()) {
            return false;
        }
        return ops.stream().anyMatch(GraphQLOperation::isStateChanging);
    }
}
