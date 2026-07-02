package com.gqlsentinel.modules;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

import com.gqlsentinel.model.DetectedEndpoint;
import com.gqlsentinel.model.GraphQLOperation;

/**
 * Common contract for the six analysis engines. Splitting the lifecycle into a passive and an
 * active hook is the central safety design of this tool:
 *
 * <ul>
 *   <li>{@link #onTraffic} — PASSIVE. Called for every in-scope GraphQL exchange we observe. It
 *       may only read what already happened; it must never send a request. Always safe to run.</li>
 *   <li>{@link #runActive} — ACTIVE. Sends crafted probes. Invoked ONLY from the UI, ONLY when the
 *       operator has armed the tool, and ONLY for in-scope endpoints (the module re-checks the
 *       {@link com.gqlsentinel.core.ScopeGate} itself as defence-in-depth).</li>
 * </ul>
 *
 * A module implements whichever hooks make sense; both have no-op defaults so, e.g., the
 * injection-surface mapper (passive only) need not pretend to have an active phase.
 */
public interface AnalysisModule {

    /** Short, stable name used in findings and the UI module list. */
    String name();

    /** One-line description shown in the config panel so operators know what each module does. */
    String description();

    /** PASSIVE hook. Never sends traffic. Default: do nothing. */
    default void onTraffic(DetectedEndpoint endpoint,
                           HttpRequestResponse exchange,
                           List<GraphQLOperation> operations) {
        // no-op by default
    }

    /** ACTIVE hook. May send bounded, scope-gated probes. Default: do nothing. */
    default void runActive(DetectedEndpoint endpoint) {
        // no-op by default
    }

    /** Whether this module has an active phase worth exposing a "run" button for. */
    default boolean supportsActive() {
        return false;
    }
}
