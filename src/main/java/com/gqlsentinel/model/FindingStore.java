package com.gqlsentinel.model;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Thread-safe registry of findings, with de-duplication and change notification.
 *
 * <p>Concurrency matters here: findings are produced from the passive proxy thread and from
 * active-testing worker threads, while the Swing UI reads them on the Event Dispatch Thread.
 * We use copy-on-write for the list (reads dominate, writes are infrequent) and a concurrent
 * set for the dedupe keys. Listeners are notified so the UI can refresh without polling.
 */
public final class FindingStore {

    private final List<Finding> findings = new CopyOnWriteArrayList<>();
    private final Set<String> seenKeys = ConcurrentHashMap.newKeySet();
    private final List<Consumer<Finding>> listeners = new CopyOnWriteArrayList<>();

    /** @return true if the finding was new and stored; false if it was a duplicate. */
    public boolean add(Finding finding) {
        if (finding == null) {
            return false;
        }
        if (!seenKeys.add(finding.dedupeKey())) {
            return false; // already reported this exact issue
        }
        findings.add(finding);
        for (Consumer<Finding> l : listeners) {
            try {
                l.accept(finding);
            } catch (RuntimeException ignored) {
                // A misbehaving UI listener must never break finding storage.
            }
        }
        return true;
    }

    /** Snapshot sorted by severity (most serious first), then newest first. */
    public List<Finding> snapshot() {
        List<Finding> copy = new ArrayList<>(findings);
        copy.sort(Comparator
                .comparing(Finding::severity)                       // enum order: HIGH first
                .thenComparing(Finding::timestamp, Comparator.reverseOrder()));
        return copy;
    }

    public int size() {
        return findings.size();
    }

    public void clear() {
        findings.clear();
        seenKeys.clear();
    }

    public void addListener(Consumer<Finding> listener) {
        listeners.add(listener);
    }
}
