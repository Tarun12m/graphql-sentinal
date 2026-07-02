package com.gqlsentinel.modules;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Pure comparison logic for field-level authorization testing. No Burp or network types here so
 * it can be unit-tested in isolation — which is exactly what you want for the piece most prone to
 * false positives and the piece an interviewer will drill into.
 *
 * <p>The question we answer: "Did a lower-privileged (or unauthenticated) principal obtain data
 * that the privileged baseline returned — i.e. data an authorization control should have blocked?"
 *
 * <h2>How false positives are minimised</h2>
 * <ol>
 *   <li><b>Denial is respected.</b> If the lower principal got HTTP 401/403, or a top-level
 *       GraphQL auth error with no data, the control worked — we emit nothing.</li>
 *   <li><b>A baseline is required.</b> We only compare fields that the privileged response
 *       actually returned as non-null. No baseline data ⇒ nothing to leak ⇒ no finding.</li>
 *   <li><b>Field-level, not blob-level.</b> We compare per top-level field, so an unrelated
 *       difference elsewhere in the response cannot trigger a finding, and the report names the
 *       exact field that leaked.</li>
 *   <li><b>Graded confidence.</b> Identical values (the lower principal saw the SAME sensitive
 *       object) are treated as a strong leak; different non-null values (field is reachable but
 *       may be row-scoped to the lower user) are flagged as weaker and marked for manual review,
 *       rather than asserted as a definite break.</li>
 *   <li><b>Errored fields are excluded.</b> A field that is null in the lower response with an
 *       error targeting it is a successful denial, not a leak.</li>
 * </ol>
 */
public final class AuthzComparator {

    public enum Outcome {
        DENIED,        // control enforced: lower principal blocked. No finding.
        NO_BASELINE,   // privileged response had no comparable data. No finding.
        INCONCLUSIVE,  // could not parse one side. No finding, but worth logging.
        LEAK           // lower principal accessed baseline fields. Finding(s) in leakedFields.
    }

    /** One field the lower principal could read. identicalValue raises confidence to "definite". */
    public record LeakedField(String name, boolean identicalValue) {}

    public record Result(Outcome outcome, List<LeakedField> leakedFields, String rationale) {
        public boolean isLeak() {
            return outcome == Outcome.LEAK && !leakedFields.isEmpty();
        }
    }

    private static final List<String> AUTH_ERROR_KEYWORDS = List.of(
            "not authori", "unauthori", "forbidden", "permission", "access denied",
            "must be logged in", "authentication", "not allowed", "denied");

    /**
     * @param privStatus  HTTP status of the privileged baseline
     * @param privBody    body of the privileged baseline response
     * @param lowerStatus HTTP status of the lower-privilege / unauth replay
     * @param lowerBody   body of the replay response
     */
    public Result compare(int privStatus, String privBody, int lowerStatus, String lowerBody) {
        // 1. Explicit HTTP denial is the clearest "control worked" signal.
        if (lowerStatus == 401 || lowerStatus == 403) {
            return new Result(Outcome.DENIED, List.of(),
                    "Lower principal received HTTP " + lowerStatus + " (access denied).");
        }

        JsonObject privData = extractData(privBody);
        if (privData == null || privData.entrySet().isEmpty()) {
            return new Result(Outcome.NO_BASELINE, List.of(),
                    "Privileged baseline returned no data to compare against.");
        }

        JsonObject lowerRoot = asObjectOrNull(lowerBody);
        if (lowerRoot == null) {
            return new Result(Outcome.INCONCLUSIVE, List.of(),
                    "Lower response was not parseable JSON.");
        }
        JsonObject lowerData = lowerRoot.has("data") && lowerRoot.get("data").isJsonObject()
                ? lowerRoot.getAsJsonObject("data") : null;

        boolean lowerHasErrors = hasNonEmptyErrors(lowerRoot);
        boolean lowerHasAnyData = lowerData != null && !lowerData.entrySet().isEmpty()
                && lowerData.entrySet().stream().anyMatch(e -> !e.getValue().isJsonNull());

        // 2. Top-level auth error and no usable data ⇒ denied.
        if (!lowerHasAnyData && lowerHasErrors && bodyLooksLikeAuthError(lowerBody)) {
            return new Result(Outcome.DENIED, List.of(),
                    "Lower principal received a GraphQL authorization error with no data.");
        }
        if (lowerData == null) {
            return new Result(Outcome.DENIED, List.of(),
                    "Lower principal received no data object.");
        }

        // 3. Field-by-field: which baseline fields did the lower principal also read?
        List<LeakedField> leaked = new ArrayList<>();
        for (Map.Entry<String, JsonElement> entry : privData.entrySet()) {
            String field = entry.getKey();
            JsonElement privVal = entry.getValue();
            if (privVal.isJsonNull() || isEmptyValue(privVal)) {
                continue; // no baseline data for this field — cannot leak what wasn't returned
            }
            if (isFieldErrored(lowerRoot, field)) {
                continue; // lower response explicitly errored this field: denial, not leak
            }
            if (!lowerData.has(field)) {
                continue;
            }
            JsonElement lowerVal = lowerData.get(field);
            if (lowerVal.isJsonNull() || isEmptyValue(lowerVal)) {
                continue; // lower got nothing for this field: control likely worked
            }
            boolean identical = privVal.equals(lowerVal);
            leaked.add(new LeakedField(field, identical));
        }

        if (leaked.isEmpty()) {
            return new Result(Outcome.DENIED, List.of(),
                    "Lower principal obtained no baseline field values.");
        }
        return new Result(Outcome.LEAK, leaked,
                "Lower principal read " + leaked.size() + " field(s) present in the privileged baseline.");
    }

    private JsonObject extractData(String body) {
        JsonObject root = asObjectOrNull(body);
        if (root == null) {
            return null;
        }
        return root.has("data") && root.get("data").isJsonObject() ? root.getAsJsonObject("data") : null;
    }

    private JsonObject asObjectOrNull(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            JsonElement el = JsonParser.parseString(body);
            return el.isJsonObject() ? el.getAsJsonObject() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private boolean hasNonEmptyErrors(JsonObject root) {
        return root.has("errors") && root.get("errors").isJsonArray()
                && root.getAsJsonArray("errors").size() > 0;
    }

    private boolean bodyLooksLikeAuthError(String body) {
        if (body == null) {
            return false;
        }
        String lower = body.toLowerCase(Locale.ROOT);
        return AUTH_ERROR_KEYWORDS.stream().anyMatch(lower::contains);
    }

    /** True if the response's errors array contains an error whose path's first element is field. */
    private boolean isFieldErrored(JsonObject root, String field) {
        if (!hasNonEmptyErrors(root)) {
            return false;
        }
        for (JsonElement err : root.getAsJsonArray("errors")) {
            if (!err.isJsonObject()) {
                continue;
            }
            JsonObject eo = err.getAsJsonObject();
            if (eo.has("path") && eo.get("path").isJsonArray()) {
                var path = eo.getAsJsonArray("path");
                if (path.size() > 0 && !path.get(0).isJsonNull()
                        && field.equals(path.get(0).getAsString())) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Treat empty arrays/objects/strings as "no data" so an empty list is not counted as a leak. */
    private boolean isEmptyValue(JsonElement el) {
        if (el.isJsonArray()) {
            return el.getAsJsonArray().isEmpty();
        }
        if (el.isJsonObject()) {
            return el.getAsJsonObject().entrySet().isEmpty();
        }
        if (el.isJsonPrimitive() && el.getAsJsonPrimitive().isString()) {
            return el.getAsString().isEmpty();
        }
        return false;
    }
}
