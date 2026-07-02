package com.gqlsentinel.core;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scope.Scope;

/**
 * The single choke point that enforces "never act on out-of-scope hosts".
 *
 * <p>Why a dedicated class instead of scattering {@code api.scope().isInScope(...)} calls?
 * Authorization is the most safety-critical invariant in this tool. Centralising it means:
 * <ul>
 *   <li>There is exactly one place to audit for correctness.</li>
 *   <li>Every module — passive detection AND active testing — is forced through the same
 *       gate, so we cannot accidentally send an active probe to a host we merely observed.</li>
 *   <li>We can add a global master switch (armed/disarmed) that instantly halts ALL active
 *       traffic regardless of scope, as a second, independent safety layer.</li>
 * </ul>
 *
 * <p>Two distinct questions are answered here and callers must pick the right one:
 * <ul>
 *   <li>{@link #isInScope(HttpRequest)} — passive observation is allowed for in-scope hosts.</li>
 *   <li>{@link #isActiveTestingAllowed(HttpRequest)} — active probing additionally requires the
 *       user to have explicitly ARMED the extension. Passive detection is always safe; sending
 *       crafted requests is not, so it is opt-in.</li>
 * </ul>
 */
public final class ScopeGate {

    private final Scope scope;
    private final ExtensionLogger logger;

    /**
     * Master arming switch for ACTIVE testing. Defaults to false ("safe / disarmed"): the
     * extension will passively detect and analyse observed traffic, but will not emit a single
     * crafted request until the operator consciously arms it in the UI. Conservative by default.
     */
    private volatile boolean activeTestingArmed = false;

    public ScopeGate(Scope scope, ExtensionLogger logger) {
        this.scope = scope;
        this.logger = logger;
    }

    public void setActiveTestingArmed(boolean armed) {
        this.activeTestingArmed = armed;
        logger.info("Active testing " + (armed ? "ARMED — crafted requests may now be sent to in-scope hosts"
                                                : "DISARMED — no crafted requests will be sent"));
    }

    public boolean isActiveTestingArmed() {
        return activeTestingArmed;
    }

    /** True if Burp's target scope includes this request's URL. Passive analysis is permitted. */
    public boolean isInScope(HttpRequest request) {
        if (request == null) {
            return false;
        }
        try {
            return scope.isInScope(request.url());
        } catch (RuntimeException e) {
            // A malformed URL should fail CLOSED (treat as out-of-scope), never open.
            logger.debug("Scope check failed for a request; treating as OUT of scope: " + e.getMessage());
            return false;
        }
    }

    /**
     * The gate every active module must call before sending any crafted request.
     * Requires BOTH in-scope AND armed. Fails closed on any doubt.
     */
    public boolean isActiveTestingAllowed(HttpRequest request) {
        if (!activeTestingArmed) {
            return false;
        }
        return isInScope(request);
    }
}
