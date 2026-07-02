package com.gqlsentinel.core;

/**
 * Central, mutable configuration for the extension. All safety-relevant bounds live here with
 * conservative defaults, so a reviewer can see the entire "how aggressive can this get?" surface
 * in one file rather than hunting through modules.
 *
 * <p>Values are volatile because they are written from the Swing UI thread and read from worker
 * threads. Setters clamp to safe ranges — the UI should never be able to configure the tool into
 * an unsafe state (e.g. a 10,000-deep query that could genuinely DoS a target).
 */
public final class Configuration {

    // ---- Depth / complexity (DoS) module bounds ---------------------------------------------
    // Absolute ceiling the tool will NEVER exceed regardless of UI input. This is the core
    // safety promise: we demonstrate a missing depth limit; we do not attempt to exhaust a server.
    public static final int HARD_MAX_DEPTH = 15;
    private volatile int maxProbeDepth = 8; // default probe depth; bounded by HARD_MAX_DEPTH

    // ---- Batching module bounds --------------------------------------------------------------
    // We prove batching is accepted with a tiny batch; we never build a brute-forcer.
    public static final int HARD_MAX_BATCH = 5;
    private volatile int probeBatchSize = 3;

    // ---- Global behaviour --------------------------------------------------------------------
    // Never replay mutations/subscriptions automatically — they can change server state.
    private volatile boolean allowStateChangingReplay = false;
    // Throttle between active requests (ms) to be a polite guest on the target.
    private volatile int activeRequestDelayMs = 250;

    public int maxProbeDepth() {
        return maxProbeDepth;
    }

    public void setMaxProbeDepth(int depth) {
        this.maxProbeDepth = clamp(depth, 1, HARD_MAX_DEPTH);
    }

    public int probeBatchSize() {
        return probeBatchSize;
    }

    public void setProbeBatchSize(int size) {
        this.probeBatchSize = clamp(size, 2, HARD_MAX_BATCH);
    }

    public boolean allowStateChangingReplay() {
        return allowStateChangingReplay;
    }

    public void setAllowStateChangingReplay(boolean allow) {
        this.allowStateChangingReplay = allow;
    }

    public int activeRequestDelayMs() {
        return activeRequestDelayMs;
    }

    public void setActiveRequestDelayMs(int ms) {
        this.activeRequestDelayMs = clamp(ms, 0, 5000);
    }

    private static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
}
